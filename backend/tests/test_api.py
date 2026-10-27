from datetime import timedelta
from uuid import uuid4
import json
from sqlalchemy import select, update
from app.models import BrowserSession, Enrollment, Endpoint, SecurityEvent, Alert, Mitigation, AuditEvent, StreamEvent, StreamHead, utcnow
from app.services import digest, verify_audit
from conftest import signin, enroll

def telemetry():
    return {'batch_id':str(uuid4()),'origin':'lab','resources':{'cpu':31,'ram':58,'disk':42,'network_bps':1024},'events':[{'title':'Lab failed logon fixture','source':'Windows Security','event_type':'authentication','windows_event_id':4625,'occurred_at':utcnow().isoformat(),'evidence':'Explicit lab-submitted event, not a monitored Windows detection.'}]}

def test_auth_required_and_no_secret_echo(client):
    for path in ['session','endpoints','events','mitigations','audit','users','stream']:
        assert client.get('/api/v1/'+path).status_code==401
    response=client.post('/api/v1/auth/login',json={'username':'admin','password':'do-not-echo','extra':'secret'},headers={'Origin':'http://127.0.0.1:3000'})
    assert response.status_code==422
    assert 'do-not-echo' not in response.text and 'secret' not in response.text

def test_login_cookie_csrf_origin_logout(client,admin):
    assert client.get('/api/v1/session').status_code==200
    cookie=client.cookies.get('sentinel_session')
    assert cookie and client.post('/api/v1/enrollments',json={'label':'test'}).status_code==403
    assert client.post('/api/v1/enrollments',json={'label':'test'},headers={**admin,'Origin':'https://wrong.example'}).status_code==403
    assert client.post('/api/v1/auth/logout',headers=admin).status_code==200
    client.cookies.set('sentinel_session',cookie)
    assert client.get('/api/v1/session').status_code==401

def test_session_expiry_and_server_user_revocation(client,admin,app):
    with app.state.sessions() as db:
        db.execute(update(BrowserSession).values(expires_at=utcnow()-timedelta(seconds=1)));db.commit()
    assert client.get('/api/v1/session').status_code==401

def test_analyst_restrictions_are_server_side(client):
    analyst=signin(client,'analyst')
    for path,body in [('enrollments',{'label':'no access'}),('users',{'username':'newuser','password':'long-enough-password','role':'administrator'}),('mitigations',{'endpoint_id':str(uuid4()),'protocol':'TCP','port':4444,'direction':'Outbound','address':'203.0.113.8','reason':'test unauthorized action'})]:
        assert client.post('/api/v1/'+path,json=body,headers=analyst).status_code==403
    assert client.get('/api/v1/audit').status_code==403
    assert client.get('/api/v1/users').status_code==403
    assert client.get('/api/v1/events').status_code==200

def test_enrollment_single_use_distinct_identity_and_no_secret_storage(client,admin,app):
    identity,payload,grant=enroll(client,admin)
    assert client.post('/api/v1/agent/enroll',json=payload).status_code==401
    other,_,_=enroll(client,admin,hostname=payload['hostname'])
    assert identity['endpointId']!=other['endpointId'] and identity['agentToken']!=other['agentToken']
    with app.state.sessions() as db:
        endpoint=db.get(Endpoint,identity['endpointId'])
        assert endpoint.credential_digest==digest(identity['agentToken'])
        assert db.get(Enrollment,grant['id']).digest==digest(grant['token'])
        assert grant['token'] not in '\n'.join(a.target for a in db.scalars(select(AuditEvent)))
    listing=client.get('/api/v1/endpoints').text
    assert identity['agentToken'] not in listing and 'credential_digest' not in listing
    assert client.get('/api/v1/endpoints').json()['items'][0]['status']=='offline'

def test_expired_and_revoked_grants_rejected(client,admin,app):
    identity,payload,grant=enroll(client,admin)
    fresh=client.post('/api/v1/enrollments',json={'label':'expiry'},headers=admin).json()
    with app.state.sessions() as db:
        db.get(Enrollment,fresh['id']).expires_at=utcnow()-timedelta(seconds=1);db.commit()
    assert client.post('/api/v1/agent/enroll',json={**payload,'token':fresh['token']}).status_code==401
    fresh=client.post('/api/v1/enrollments',json={'label':'revoked'},headers=admin).json()
    assert client.post(f"/api/v1/enrollments/{fresh['id']}/revoke",headers=admin).status_code==200
    assert client.post('/api/v1/agent/enroll',json={**payload,'token':fresh['token']}).status_code==401

def test_ingestion_identity_binding_validation_dedup_and_persistence(client,admin,app):
    identity,_,_=enroll(client,admin);body=telemetry();auth={'Authorization':'Bearer '+identity['agentToken']}
    assert client.post('/api/v1/agent/telemetry',json=body).status_code==401
    assert client.post('/api/v1/agent/telemetry',json=body,headers=admin).status_code==401
    assert client.post('/api/v1/agent/telemetry',json={**body,'endpoint_id':str(uuid4())},headers=auth).status_code==422
    spoofed=telemetry();spoofed['events'][0]['severity']='critical'
    assert client.post('/api/v1/agent/telemetry',json=spoofed,headers=auth).status_code==422
    first=client.post('/api/v1/agent/telemetry',json=body,headers=auth)
    assert first.status_code==202,first.text
    assert client.post('/api/v1/agent/telemetry',json=body,headers=auth).json()['duplicate'] is True
    changed={**body,'resources':{**body['resources'],'cpu':80}}
    assert client.post('/api/v1/agent/telemetry',json=changed,headers=auth).status_code==409
    assert client.post('/api/v1/agent/telemetry',json={**body,'batch_id':str(uuid4()),'resources':{**body['resources'],'cpu':999}},headers=auth).status_code==422
    host=client.get('/api/v1/endpoints').json()['items'][0]
    assert host['status']=='online' and host['cpu']==31 and host['origin']=='lab'
    events=client.get('/api/v1/events').json()
    assert events['total']==1 and events['items'][0]['severity']=='medium' and events['items'][0]['origin']=='lab'
    assert client.get('/api/v1/events?severity=critical').json()['total']==0
    assert client.get('/api/v1/events?q=explicit&type=authentication&source=Windows%20Security').json()['total']==1
    with app.state.sessions() as db:
        assert len(db.scalars(select(Alert)).all())==1
        assert [s.sequence for s in db.scalars(select(StreamEvent).order_by(StreamEvent.sequence))]==[1,2,3]

def test_revoked_endpoint_cannot_report(client,admin):
    identity,_,_=enroll(client,admin)
    assert client.post(f"/api/v1/endpoints/{identity['endpointId']}/revoke",headers=admin).status_code==200
    assert client.post('/api/v1/agent/telemetry',json=telemetry(),headers={'Authorization':'Bearer '+identity['agentToken']}).status_code==401
    assert client.get('/api/v1/endpoints').json()['items'][0]['status']=='revoked'

def test_investigation_persists_and_analyst_can_review(client,admin):
    identity,_,_=enroll(client,admin)
    client.post('/api/v1/agent/telemetry',json=telemetry(),headers={'Authorization':'Bearer '+identity['agentToken']})
    event=client.get('/api/v1/events').json()['items'][0]
    headers=signin(client,'analyst')
    assert client.patch(f"/api/v1/events/{event['id']}",json={'status':'investigating'},headers=headers).status_code==200
    assert client.get('/api/v1/events').json()['items'][0]['status']=='investigating'

def test_mitigation_only_proposes_and_preserves_scope(client,admin,app):
    identity,_,_=enroll(client,admin)
    body={'endpoint_id':identity['endpointId'],'protocol':'TCP','port':4444,'direction':'Outbound','address':'203.0.113.87','reason':'Investigation proposal in an isolated test lab','ttl_minutes':30}
    for invalid in [{**body,'port':3389},{**body,'address':'0.0.0.0'},{**body,'address':'255.255.255.255'},{**body,'ttl_minutes':9999}]:
        assert client.post('/api/v1/mitigations',json=invalid,headers=admin).status_code==422
    response=client.post('/api/v1/mitigations',json=body,headers=admin)
    assert response.status_code==201,response.text
    item=response.json();assert item['status']=='pending approval' and item['executionVerified'] is False
    assert client.post('/api/v1/mitigations',json=body,headers=admin).status_code==409
    assert client.post(f"/api/v1/mitigations/{item['id']}/approve",headers=admin).status_code==409
    with app.state.sessions() as db: assert db.get(Mitigation,item['id']).status=='pending approval'

def test_tamper_evident_audit_detects_edit(client,admin,app):
    assert client.get('/api/v1/audit/verify').json()['valid'] is True
    with app.state.sessions() as db:
        row=db.scalar(select(AuditEvent).order_by(AuditEvent.sequence));row.action='edited';db.commit()
    assert client.get('/api/v1/audit/verify').json()['valid'] is False

def test_login_rate_limit_and_input_size(app):
    from fastapi.testclient import TestClient
    app.state.settings.login_limit=2
    with TestClient(app) as client:
        for _ in range(2): assert client.post('/api/v1/auth/login',json={'username':'admin','password':'wrong'},headers={'Origin':'http://127.0.0.1:3000'}).status_code==401
        assert client.post('/api/v1/auth/login',json={'username':'admin','password':'wrong'},headers={'Origin':'http://127.0.0.1:3000'}).status_code==429
        assert client.post('/api/v1/auth/login',content=b'x'*(1_048_577),headers={'Content-Type':'application/json'}).status_code==413

def test_production_configuration_and_tls(settings):
    import pytest
    from pydantic import ValidationError
    from app.config import Settings
    from app.main import create_app
    from fastapi.testclient import TestClient
    with pytest.raises(ValidationError): Settings(environment='production',database_url='sqlite:///no.sqlite',session_secret='short')
    with pytest.raises(ValidationError): Settings(environment='test',database_url='sqlite:///no.sqlite',session_secret='GENERATE_A_RANDOM_VALUE_WITH_AT_LEAST_32_CHARACTERS')
    production=settings.model_copy(update={'environment':'production'})
    with TestClient(create_app(production)) as client:
        assert client.get('/health').status_code==403

def test_users_deactivation_invalidates_sessions(client,admin):
    response=client.post('/api/v1/users',json={'username':'newanalyst','password':'test-only-long-password','role':'analyst'},headers=admin)
    assert response.status_code==201
    user=response.json()
    from fastapi.testclient import TestClient
    with TestClient(client.app) as second:
        signin(second,'newanalyst')
        assert client.post(f"/api/v1/users/{user['id']}/deactivate",headers=admin).status_code==200
        assert second.get('/api/v1/session').status_code==401

def test_no_mock_data_seeded_and_intelligence_is_not_claimed(client,admin):
    assert client.get('/api/v1/endpoints').json()['total']==0
    assert client.get('/api/v1/events').json()['total']==0
    assert client.get('/api/v1/intelligence').json()['status']=='not_configured'
    assert client.get('/api/v1/session').json()['capabilities']['commands'] is False


def test_housekeeping_expires_proposals_and_emits_audited_state(client,admin,app):
    from app.main import maintain_once
    identity,_,_=enroll(client,admin)
    body={'endpoint_id':identity['endpointId'],'protocol':'TCP','port':4444,'direction':'Outbound','address':'203.0.113.87','reason':'A bounded lab review proposal','ttl_minutes':15}
    item=client.post('/api/v1/mitigations',json=body,headers=admin).json()
    with app.state.sessions() as db:
        db.get(Mitigation,item['id']).expires_at=utcnow()-timedelta(seconds=1);db.commit()
    maintain_once(app.state.sessions)
    with app.state.sessions() as db:
        assert db.get(Mitigation,item['id']).status=='expired'
        assert db.scalar(select(AuditEvent).where(AuditEvent.action=='mitigation.expired',AuditEvent.target==item['id'])) is not None
        assert db.scalars(select(StreamEvent).order_by(StreamEvent.sequence.desc())).first().data['status']=='expired'
        assert verify_audit(db) is True
