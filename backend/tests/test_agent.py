from copy import deepcopy
from datetime import timedelta
from uuid import uuid4
from app.models import utcnow
from conftest import enroll

def setup(client,admin):
    identity,_,_=enroll(client,admin)
    assert identity['protocolVersion']==3
    return identity,{'Authorization':'Bearer '+identity['agentToken']}

def body():
    return {'batch_id':str(uuid4()),'origin':'agent','sampled_at':utcnow().isoformat(),'resources':{'cpu':12,'ram':40,'disk':33,'network_bps':10},'events':[]}

def event(**changes):
    return dict(event_uid=str(uuid4()),title='Agent protocol fixture',source='Windows EventLog:Security',event_type='process',occurred_at=utcnow().isoformat(),evidence='Explicit test fixture; not a real Windows observation.',**changes)

def post(client,auth,payload):
    response=client.post('/api/v1/agent/telemetry',json=payload,headers=auth)
    assert response.status_code==202,response.text
    assert response.json()['batchId']==payload['batch_id']
    return response.json()

def test_stable_events_deduplicate_across_batches_and_reject_mutation(client,admin):
    _,auth=setup(client,admin);first=body();first['events']=[event(signals=['sensitive_file_changed'])]
    assert post(client,auth,first)['events']==1
    retry=deepcopy(first);retry['batch_id']=str(uuid4())
    assert post(client,auth,retry)['events']==0
    retry['batch_id']=str(uuid4());retry['events'][0]['title']='Mutated identity'
    assert client.post('/api/v1/agent/telemetry',json=retry,headers=auth).status_code==409
    assert client.get('/api/v1/events').json()['total']==1

def test_inventory_health_limits_and_out_of_order_snapshots(client,admin):
    identity,auth=setup(client,admin);fresh=body()
    fresh['inventory']={'processes':[{'pid':1,'name':'fixture','path':'','parent':'','signature':'unavailable'}],'services':[],'software':[{'name':'Fixture','version':'1','publisher':'Lab'}],'truncated':False}
    fresh['health']={'collectors':[{'name':'Security','status':'unavailable','message':'Audit policy unavailable'}],'queue_pending':3,'dropped_records':2,'agent_version':'0.3.0'}
    post(client,auth,fresh)
    listed=client.get('/api/v1/endpoints').json()['items'][0]
    assert listed['inventoryAvailable'] is True and not listed.get('inventory')
    host=client.get('/api/v1/endpoints/'+identity['endpointId']).json()
    assert host['inventory']['processes'][0]['name']=='fixture' and host['agentHealth']['queue_pending']==3
    stale=deepcopy(fresh);stale.update(batch_id=str(uuid4()),sampled_at=(utcnow()-timedelta(hours=1)).isoformat())
    stale['inventory']['software'][0]['version']='old';stale['resources']['cpu']=99
    post(client,auth,stale)
    host=client.get('/api/v1/endpoints/'+identity['endpointId']).json()
    assert host['inventory']['software'][0]['version']=='1' and host['cpu']==12
    oversized=deepcopy(fresh);oversized['batch_id']=str(uuid4());oversized['inventory']['processes']*=201
    assert client.post('/api/v1/agent/telemetry',json=oversized,headers=auth).status_code==422
    secret=body();secret['events']=[event(details={'command_line':'secret'})]
    assert client.post('/api/v1/agent/telemetry',json=secret,headers=auth).status_code==422

def test_layered_rules_do_not_treat_signatures_as_verdicts(client,admin):
    _,auth=setup(client,admin);payload=body()
    payload['events']=[event(signals=['unsigned_image']),event(signals=['encoded_powershell','unusual_parent'],details={'signature_status':'valid_cached_chain'}),event(signals=['temp_execution','unsigned_image']),event(signals=['known_hash_indicator'],details={'image_sha256':'a'*64,'rule_hash_source':'operator_local_config'})]
    post(client,auth,payload)
    events=client.get('/api/v1/events').json()['items'];by_uid={e['rule']:e for e in events}
    assert sorted(e['severity'] for e in events)==['high','high','low','medium']
    assert any('ENCODED-PARENT' in rule and e['severity']=='high' for rule,e in by_uid.items())
    assert any(e['signals']==['unsigned_image'] and e['severity']=='low' for e in events)

def test_authentication_burst_is_scoped_to_endpoint_source_and_window(client,admin):
    _,auth=setup(client,admin);payload=body();stamp=utcnow()-timedelta(seconds=10)
    payload['events']=[{**event(windows_event_id=4625,signals=['auth_failure'],details={'source_address':'192.0.2.23'}),'event_type':'authentication','occurred_at':(stamp+timedelta(seconds=i)).isoformat()} for i in range(5)]
    post(client,auth,payload)
    events=client.get('/api/v1/events').json()['items']
    assert sum(e['severity']=='high' for e in events)==1
    separate=body();separate['events']=[event(windows_event_id=4625,details={'source_address':'192.0.2.24'})];separate['events'][0]['event_type']='authentication'
    post(client,auth,separate)
    assert sum(e['severity']=='high' for e in client.get('/api/v1/events').json()['items'])==1
