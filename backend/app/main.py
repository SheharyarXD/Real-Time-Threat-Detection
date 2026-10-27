import asyncio
import hashlib
import hmac
import json
import logging
from threading import BoundedSemaphore
from contextlib import asynccontextmanager
from datetime import timedelta
from uuid import UUID
from typing import Literal
from fastapi import FastAPI, Depends, HTTPException, Request, Response, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware
from sqlalchemy import select, delete, func, or_
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from .config import Settings, load_settings
from .database import database
from .models import User, BrowserSession, Enrollment, Endpoint, TelemetryBatch, SecurityEvent, Alert, Mitigation, AuditEvent, AuditHead, StreamEvent, StreamHead, RateBucket, utcnow
from .schemas import Login, UserInput, EnrollmentInput, AgentEnrollment, Telemetry, EventStatus, MitigationInput
from .security import COOKIE, get_db, browser_user, administrator, endpoint_user, lookup_session, origin_allowed, limit
from .services import new_token, digest, csrf_token, password_hasher, password_valid, DUMMY_HASH, aware, iso, audit, emit, endpoint_json, event_json, mitigation_json, normalize, page, verify_audit, PROTECTED_PORTS
from .middleware import SecurityMiddleware

logger = logging.getLogger("sentinel")
login_slots = BoundedSemaphore(4)

def maintain_once(sessions):
    with sessions() as db:
        expired=db.scalars(select(Mitigation).where(Mitigation.status=="pending approval",Mitigation.expires_at<=utcnow()).with_for_update()).all()
        for item in expired:
            item.status="expired"
            audit(db,"system","mitigation.expired",item.id)
            emit(db,"mitigation.changed",mitigation_json(item))
        db.execute(delete(RateBucket).where(RateBucket.expires_at<utcnow()))
        db.execute(delete(BrowserSession).where(BrowserSession.expires_at<utcnow()))
        db.commit()

async def housekeeping(app):
    while True:
        try: await asyncio.to_thread(maintain_once,app.state.sessions)
        except asyncio.CancelledError: raise
        except Exception: logger.error("Housekeeping failed; database state will be retried")
        await asyncio.sleep(30)

def create_app(settings=None):
    settings = settings or load_settings()
    logging.basicConfig(level=logging.INFO,format="%(message)s")
    engine, sessions = database(settings)
    @asynccontextmanager
    async def lifespan(app):
        with sessions() as db:
            if db.get(AuditHead, 1) is None or db.get(StreamHead, 1) is None:
                raise RuntimeError("Run alembic upgrade head before starting the backend")
        task = asyncio.create_task(housekeeping(app))
        yield
        task.cancel()
        try: await task
        except asyncio.CancelledError: pass
        engine.dispose()
    def global_budget(request: Request):
        limit(request,"http",request.client.host if request.client else "unknown",settings.request_limit)

    app = FastAPI(dependencies=[Depends(global_budget)], title="Sentinel API", version="0.2.0", lifespan=lifespan, docs_url="/docs" if settings.environment != "production" else None, redoc_url=None)
    app.state.settings, app.state.engine, app.state.sessions = settings, engine, sessions
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    app.add_middleware(SecurityMiddleware, settings=settings)

    @app.exception_handler(HTTPException)
    async def http_error(request, exc):
        if exc.status_code in {401, 403}:
            def record():
                with sessions() as db:
                    audit(db, getattr(request.state,"actor","anonymous"), "access.denied", request.url.path, str(exc.status_code))
                    db.commit()
            try: await asyncio.to_thread(record)
            except SQLAlchemyError: logger.error("Could not persist denied-access audit")
        return JSONResponse({"code":f"http_{exc.status_code}","message":exc.detail,"requestId":getattr(request.state,"request_id",None)}, status_code=exc.status_code, headers=exc.headers)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # Pydantic's default error includes rejected input; passwords/tokens must not echo.
        fields = [{"path":".".join(map(str,e["loc"])),"message":e["msg"]} for e in exc.errors()]
        return JSONResponse({"code":"validation_error","message":"Request validation failed","fields":fields,"requestId":request.state.request_id},422)

    @app.exception_handler(SQLAlchemyError)
    async def database_error(request, exc):
        logger.error("Database operation failed; requestId=%s", request.state.request_id)
        return JSONResponse({"code":"database_unavailable","message":"Database operation could not complete","requestId":request.state.request_id},503)

    @app.get("/health")
    def health(): return {"service":"sentinel","milestone":2}

    @app.get("/api/v1/session")
    def session_info(request: Request, user=Depends(browser_user)):
        return {"user":{"id":user.id,"username":user.username,"role":user.role},"csrfToken":csrf_token(request.cookies[COOKIE],settings.session_secret.get_secret_value()),"capabilities":{"enrollment":True,"telemetry":True,"stream":True,"commands":False,"intelligence":False},"mode":"backend"}

    @app.post("/api/v1/auth/login")
    def login(body: Login, request: Request, response: Response, db=Depends(get_db)):
        origin_allowed(request)
        limit(request,"login-ip",request.client.host if request.client else "unknown",30)
        limit(request,"login",body.username.lower(),settings.login_limit,300)
        user = db.scalar(select(User).where(User.username == body.username.lower()))
        if not login_slots.acquire(blocking=False): raise HTTPException(429,"Login service is busy; retry shortly",headers={"Retry-After":"1"})
        try: valid = password_valid(body.password, user.password_hash if user else DUMMY_HASH)
        finally: login_slots.release()
        if not user or not user.active or not valid:
            audit(db,"anonymous","login.failed",body.username.lower(),"denied")
            db.commit()
            raise HTTPException(401,"Invalid username or password")
        # Rotate any existing browser session when signing in again.
        if old := request.cookies.get(COOKIE):
            existing = db.get(BrowserSession,digest(old))
            if existing: existing.revoked=True
        raw = new_token()
        db.add(BrowserSession(digest=digest(raw),user_id=user.id,expires_at=utcnow()+timedelta(hours=settings.session_hours)))
        audit(db,user.username,"login.succeeded",user.id)
        db.commit()
        response.set_cookie(COOKIE,raw,httponly=True,secure=settings.secure_cookie,samesite="strict",max_age=settings.session_hours*3600,path="/api/v1")
        return {"user":{"id":user.id,"username":user.username,"role":user.role},"csrfToken":csrf_token(raw,settings.session_secret.get_secret_value())}

    @app.post("/api/v1/auth/logout")
    def logout(request: Request,response: Response,user=Depends(browser_user),db=Depends(get_db)):
        db.get(BrowserSession,digest(request.cookies[COOKIE])).revoked=True
        audit(db,user.username,"logout",user.id)
        db.commit()
        response.delete_cookie(COOKIE,path="/api/v1",secure=settings.secure_cookie,httponly=True,samesite="strict")
        return {"ok":True}

    @app.get("/api/v1/users")
    def users(user=Depends(administrator),db=Depends(get_db)):
        return {"items":[{"id":u.id,"username":u.username,"role":u.role,"active":u.active} for u in db.scalars(select(User).order_by(User.username))]}

    @app.post("/api/v1/users",status_code=201)
    def add_user(body: UserInput,user=Depends(administrator),db=Depends(get_db)):
        if db.scalar(select(User.id).where(User.username==body.username.lower())): raise HTTPException(409,"Username is already registered")
        item=User(username=body.username.lower(),password_hash=password_hasher.hash(body.password),role=body.role)
        db.add(item); db.flush()
        audit(db,user.username,"user.created",item.id)
        db.commit()
        return {"id":item.id,"username":item.username,"role":item.role,"active":item.active}

    @app.post("/api/v1/users/{user_id}/deactivate")
    def deactivate(user_id: UUID,user=Depends(administrator),db=Depends(get_db)):
        item=db.get(User,str(user_id))
        if not item: raise HTTPException(404,"User not found")
        if item.id==user.id: raise HTTPException(409,"Self-deactivation is not permitted")
        item.active=False
        audit(db,user.username,"user.deactivated",item.id)
        db.commit()
        return {"ok":True}

    @app.post("/api/v1/enrollments",status_code=201)
    def grant(body: EnrollmentInput,user=Depends(administrator),db=Depends(get_db)):
        token=new_token()
        item=Enrollment(digest=digest(token),label=body.label,group=body.group,created_by=user.id,expires_at=utcnow()+timedelta(minutes=15))
        db.add(item); db.flush()
        audit(db,user.username,"enrollment.created",item.id)
        db.commit()
        return {"id":item.id,"token":token,"expiresAt":iso(item.expires_at),"singleUse":True}

    @app.get("/api/v1/enrollments")
    def grants(user=Depends(administrator),db=Depends(get_db)):
        return {"items":[{"id":e.id,"label":e.label,"group":e.group,"expiresAt":iso(e.expires_at),"usedAt":iso(e.used_at),"revoked":e.revoked} for e in db.scalars(select(Enrollment).order_by(Enrollment.expires_at.desc()).limit(100))]}

    @app.post("/api/v1/enrollments/{grant_id}/revoke")
    def revoke_grant(grant_id: UUID,user=Depends(administrator),db=Depends(get_db)):
        item=db.scalar(select(Enrollment).where(Enrollment.id==str(grant_id)).with_for_update())
        if not item: raise HTTPException(404,"Enrollment not found")
        item.revoked=True
        audit(db,user.username,"enrollment.revoked",item.id)
        db.commit()
        return {"ok":True}

    @app.post("/api/v1/agent/enroll",status_code=201)
    def enroll(body: AgentEnrollment,request: Request,db=Depends(get_db)):
        limit(request,"enroll",request.client.host if request.client else "unknown",20)
        grant=db.scalar(select(Enrollment).where(Enrollment.digest==digest(body.token)).with_for_update())
        if not grant or grant.revoked or grant.used_at or aware(grant.expires_at)<=utcnow(): raise HTTPException(401,"Enrollment token is invalid, expired, revoked or already consumed")
        raw=new_token()
        host=Endpoint(enrollment_id=grant.id,credential_digest=digest(raw),hostname=body.hostname,ip=str(body.ip),os=body.os,agent_version=body.agent_version,group=grant.group)
        grant.used_at=utcnow()
        db.add(host)
        try: db.flush()
        except IntegrityError:
            db.rollback()
            raise HTTPException(401,"Enrollment token has already been consumed")
        audit(db,f"endpoint:{host.id}","endpoint.enrolled",host.id)
        emit(db,"endpoint.changed",endpoint_json(host))
        db.commit()
        return {"endpointId":host.id,"agentToken":raw,"credentialShownOnce":True,"commandsEnabled":False,"protocolVersion":3}

    @app.get("/api/v1/endpoints")
    def endpoints(q: str=Query(default="",max_length=100),status: Literal["online","offline","degraded","revoked"]|None=None,offset: int=Query(default=0,ge=0),limit_: int=Query(default=100,ge=1,le=200,alias="limit"),user=Depends(browser_user),db=Depends(get_db)):
        stmt=select(Endpoint).order_by(Endpoint.created_at.desc())
        if status:
            cutoff=utcnow()-timedelta(seconds=120)
            if status=="revoked": stmt=stmt.where(Endpoint.revoked.is_(True))
            elif status=="offline": stmt=stmt.where(Endpoint.revoked.is_(False),or_(Endpoint.last_seen.is_(None),Endpoint.last_seen<=cutoff))
            elif status=="degraded": stmt=stmt.where(Endpoint.revoked.is_(False),Endpoint.last_seen>cutoff,or_(Endpoint.cpu>85,Endpoint.ram>90))
            else: stmt=stmt.where(Endpoint.revoked.is_(False),Endpoint.last_seen>cutoff,Endpoint.cpu<=85,Endpoint.ram<=90)
        if q: stmt=stmt.where(or_(Endpoint.hostname.ilike(f"%{q}%"),Endpoint.ip.ilike(f"%{q}%")))
        return page(db,stmt,endpoint_json,offset,limit_)

    @app.get("/api/v1/endpoints/{endpoint_id}")
    def endpoint(endpoint_id: UUID,user=Depends(browser_user),db=Depends(get_db)):
        host=db.get(Endpoint,str(endpoint_id))
        if not host: raise HTTPException(404,"Endpoint not found")
        return endpoint_json(host,include_inventory=True)

    @app.post("/api/v1/endpoints/{endpoint_id}/revoke")
    def revoke_endpoint(endpoint_id: UUID,user=Depends(administrator),db=Depends(get_db)):
        host=db.scalar(select(Endpoint).where(Endpoint.id==str(endpoint_id)).with_for_update())
        if not host: raise HTTPException(404,"Endpoint not found")
        host.revoked=True
        audit(db,user.username,"endpoint.revoked",host.id)
        emit(db,"endpoint.changed",endpoint_json(host))
        db.commit()
        return {"ok":True}

    @app.post("/api/v1/agent/telemetry",status_code=202)
    def telemetry(body: Telemetry,request: Request,host=Depends(endpoint_user),db=Depends(get_db)):
        payload_hash=digest(json.dumps(body.model_dump(mode="json"),sort_keys=True,separators=(",",":")))
        previous=db.scalar(select(TelemetryBatch).where(TelemetryBatch.endpoint_id==host.id,TelemetryBatch.batch_id==str(body.batch_id)))
        if previous:
            if not hmac.compare_digest(previous.payload_hash,payload_hash): raise HTTPException(409,"Batch ID was reused with different content")
            return {"accepted":True,"duplicate":True,"events":0,"batchId":str(body.batch_id)}
        batch=TelemetryBatch(endpoint_id=host.id,batch_id=str(body.batch_id),payload_hash=payload_hash)
        db.add(batch); db.flush()
        host.last_seen=utcnow()
        sampled=body.sampled_at or utcnow()
        if host.resource_observed_at is None or sampled>=aware(host.resource_observed_at):
            host.cpu,host.ram,host.disk,host.network_bps=body.resources.cpu,body.resources.ram,body.resources.disk,body.resources.network_bps
            host.resource_observed_at=sampled;host.telemetry_origin=body.origin
            if body.health: host.agent_health=body.health.model_dump(mode="json");host.agent_version=body.health.agent_version
        if body.inventory and (host.inventory_observed_at is None or sampled>=aware(host.inventory_observed_at)):
            host.inventory=body.inventory.model_dump(mode="json");host.inventory_observed_at=sampled
        records=[]
        for item in body.events:
            event_hash=digest(json.dumps(item.model_dump(mode="json"),sort_keys=True,separators=(",",":")))
            if item.event_uid:
                existing=db.scalar(select(SecurityEvent).where(SecurityEvent.endpoint_id==host.id,SecurityEvent.external_id==str(item.event_uid)))
                if existing:
                    if existing.external_hash!=event_hash: raise HTTPException(409,"External event ID reused with different content")
                    continue
            recent=0
            if item.event_type=="authentication" and item.windows_event_id==4625:
                recent=db.scalar(select(func.count()).select_from(SecurityEvent).where(SecurityEvent.endpoint_id==host.id,SecurityEvent.windows_event_id==4625,SecurityEvent.occurred_at>=item.occurred_at-timedelta(minutes=2),SecurityEvent.occurred_at<=item.occurred_at,func.coalesce(SecurityEvent.details["source_address"].as_string(),"")==item.details.get("source_address","")))
            severity,confidence,rule=normalize(item,recent)
            event=SecurityEvent(external_id=str(item.event_uid) if item.event_uid else None,external_hash=event_hash if item.event_uid else None,signals=item.signals,details=item.details,endpoint_id=host.id,batch_id=batch.id,title=item.title,source=item.source,event_type=item.event_type,windows_event_id=item.windows_event_id,occurred_at=item.occurred_at,severity=severity,confidence=confidence,rule=rule,evidence=item.evidence,telemetry_origin=body.origin)
            db.add(event); db.flush()
            alert=None
            if severity in {"medium","high","critical"}:
                alert=Alert(event_id=event.id); db.add(alert); db.flush()
            records.append(event_json(event,alert))
        audit(db,f"endpoint:{host.id}","telemetry.accepted",batch.id)
        emit(db,"endpoint.changed",endpoint_json(host))
        for record in records: emit(db,"event.created",record)
        db.commit()
        return {"accepted":True,"duplicate":False,"events":len(records),"batchId":str(body.batch_id)}

    @app.get("/api/v1/events")
    def events(q: str=Query(default="",max_length=100),severity: str|None=None,endpoint: UUID|None=None,type: str|None=None,source: str|None=None,offset: int=Query(default=0,ge=0),limit_: int=Query(default=100,ge=1,le=200,alias="limit"),user=Depends(browser_user),db=Depends(get_db)):
        stmt=select(SecurityEvent).order_by(SecurityEvent.received_at.desc(),SecurityEvent.id)
        if q: stmt=stmt.where(or_(SecurityEvent.title.ilike(f"%{q}%"),SecurityEvent.evidence.ilike(f"%{q}%")))
        if severity: stmt=stmt.where(SecurityEvent.severity==severity)
        if endpoint: stmt=stmt.where(SecurityEvent.endpoint_id==str(endpoint))
        if type: stmt=stmt.where(SecurityEvent.event_type==type)
        if source: stmt=stmt.where(SecurityEvent.source==source)
        return page(db,stmt,lambda e:event_json(e,db.scalar(select(Alert).where(Alert.event_id==e.id))),offset,limit_)

    @app.patch("/api/v1/events/{event_id}")
    def event_status(event_id: UUID,body: EventStatus,user=Depends(browser_user),db=Depends(get_db)):
        event=db.get(SecurityEvent,str(event_id))
        if not event: raise HTTPException(404,"Event not found")
        alert=db.scalar(select(Alert).where(Alert.event_id==event.id).with_for_update())
        if not alert: raise HTTPException(409,"This recorded event has no alert")
        alert.status,alert.updated_at=body.status,utcnow()
        audit(db,user.username,"alert.status_changed",event.id)
        result=event_json(event,alert)
        emit(db,"event.changed",result); db.commit()
        return result

    @app.get("/api/v1/mitigations")
    def mitigations(offset: int=Query(default=0,ge=0),user=Depends(browser_user),db=Depends(get_db)):
        return page(db,select(Mitigation).order_by(Mitigation.created_at.desc()),mitigation_json,offset,100)

    @app.post("/api/v1/mitigations",status_code=201)
    def propose(body: MitigationInput,user=Depends(administrator),db=Depends(get_db)):
        host=db.scalar(select(Endpoint).where(Endpoint.id==str(body.endpoint_id)).with_for_update())
        if not host or host.revoked: raise HTTPException(409,"Endpoint is unavailable or revoked")
        if body.port in PROTECTED_PORTS: raise HTTPException(422,"Management and essential service ports are protected")
        if body.address.is_multicast or body.address.is_unspecified or body.address.is_loopback or str(body.address)=="255.255.255.255": raise HTTPException(422,"Choose a scoped remote unicast address")
        duplicate=db.scalar(select(Mitigation.id).where(Mitigation.endpoint_id==host.id,Mitigation.port==body.port,Mitigation.protocol==body.protocol,Mitigation.direction==body.direction,Mitigation.address==str(body.address),Mitigation.status.in_(["pending approval","queued","applied"]),Mitigation.expires_at>utcnow()))
        if duplicate: raise HTTPException(409,"An active proposal already covers this scope")
        item=Mitigation(endpoint_id=host.id,requested_by=user.id,protocol=body.protocol,port=body.port,direction=body.direction,address=str(body.address),reason=body.reason,expires_at=utcnow()+timedelta(minutes=body.ttl_minutes))
        db.add(item); db.flush()
        audit(db,user.username,"mitigation.proposed",item.id)
        result=mitigation_json(item); emit(db,"mitigation.changed",result); db.commit()
        return result

    @app.post("/api/v1/mitigations/{mitigation_id}/{action}")
    def response_action(mitigation_id: UUID,action: str,user=Depends(administrator)):
        raise HTTPException(409,"Endpoint commands and firewall execution are unavailable until Milestone 5")

    @app.get("/api/v1/intelligence")
    def intelligence(user=Depends(browser_user)):
        return {"items":[],"status":"not_configured","message":"Intelligence integration begins in Milestone 4"}

    @app.get("/api/v1/audit")
    def audits(offset: int=Query(default=0,ge=0),user=Depends(administrator),db=Depends(get_db)):
        return page(db,select(AuditEvent).order_by(AuditEvent.sequence.desc()),lambda a:dict(id=str(a.sequence),time=a.created_at,actor=a.actor,action=a.action,target=a.target,outcome=a.outcome,previousHash=a.previous_hash,hash=a.digest),offset,100)

    @app.get("/api/v1/audit/verify")
    def audit_verify(user=Depends(administrator),db=Depends(get_db)): return {"valid":verify_audit(db)}

    def read_stream(raw,cursor):
        with sessions() as db:
            if lookup_session(db,raw) is None: return None
            return [dict(sequence=e.sequence,timestamp=iso(e.created_at),type=e.event_type,data=e.data) for e in db.scalars(select(StreamEvent).where(StreamEvent.sequence>cursor).order_by(StreamEvent.sequence).limit(100))]

    def stream_user(request: Request):
        with sessions() as db:
            user=lookup_session(db,request.cookies.get(COOKIE))
            if not user: raise HTTPException(401,"Authentication required")
            request.state.actor=user.username
            return user

    @app.get("/api/v1/stream")
    async def stream(request: Request,after: int=Query(default=0,ge=0),user=Depends(stream_user)):
        raw=request.cookies[COOKIE]
        try: cursor=max(after,int(request.headers.get("last-event-id","0")))
        except ValueError: raise HTTPException(400,"Invalid stream cursor")
        if cursor<0: raise HTTPException(400,"Invalid stream cursor")
        async def generate():
            nonlocal cursor
            yield ": connected\n\n"
            while not await request.is_disconnected():
                records=await asyncio.to_thread(read_stream,raw,cursor)
                if records is None:
                    yield 'event: session.expired\ndata: {}\n\n'
                    return
                for record in records:
                    cursor=record["sequence"]
                    yield f'id: {cursor}\nevent: platform\ndata: {json.dumps(record,separators=(",",":"))}\n\n'
                yield ": heartbeat\n\n"
                await asyncio.sleep(settings.stream_seconds)
        return StreamingResponse(generate(),media_type="text/event-stream",headers={"X-Accel-Buffering":"no","Cache-Control":"no-store"})

    return app
