import hashlib
import hmac
import time
from datetime import timedelta
from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from .models import BrowserSession, User, Endpoint, RateBucket, utcnow
from .services import digest, csrf_token, aware

COOKIE = "sentinel_session"

def get_db(request: Request):
    with request.app.state.sessions() as db:
        yield db

def limit(request, scope, identity, maximum, seconds=60):
    factory = request.app.state.sessions
    settings = request.app.state.settings
    window = int(time.time()) // seconds
    key = f"{scope}:{hmac.new(settings.session_secret.get_secret_value().encode(), str(identity).encode(), hashlib.sha256).hexdigest()}:{window}"
    # Atomic upsert works across workers. Rate state is not an in-memory bypassable counter.
    with factory() as db:
        insert = pg_insert if db.bind.dialect.name == "postgresql" else sqlite_insert
        stmt = insert(RateBucket).values(key=key, count=1, expires_at=utcnow() + timedelta(seconds=seconds*2))
        stmt = stmt.on_conflict_do_update(index_elements=[RateBucket.key], set_={"count": RateBucket.count + 1}).returning(RateBucket.count)
        count = db.scalar(stmt)
        db.commit()
    if count > maximum: raise HTTPException(429, "Rate limit exceeded", headers={"Retry-After": str(seconds)})

def origin_allowed(request):
    if request.headers.get("origin") not in request.app.state.settings.allowed_origins:
        raise HTTPException(403, "Browser origin is not allowed")

def lookup_session(db, raw):
    item = db.get(BrowserSession, digest(raw)) if raw else None
    if item is None or item.revoked or aware(item.expires_at) <= utcnow(): return None
    user = db.get(User, item.user_id)
    return user if user and user.active else None

def browser_user(request: Request, db=Depends(get_db)):
    raw = request.cookies.get(COOKIE)
    user = lookup_session(db, raw)
    if user is None: raise HTTPException(401, "Authentication required")
    request.state.actor = user.username
    if request.method not in {"GET", "HEAD", "OPTIONS"}:
        origin_allowed(request)
        expected = csrf_token(raw, request.app.state.settings.session_secret.get_secret_value())
        if not hmac.compare_digest(request.headers.get("x-csrf-token", ""), expected): raise HTTPException(403, "CSRF validation failed")
    return user

def administrator(user=Depends(browser_user)):
    if user.role != "administrator": raise HTTPException(403, "Administrator permission required")
    return user

def endpoint_user(request: Request, db=Depends(get_db)):
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not 32 <= len(token) <= 128: raise HTTPException(401, "Endpoint authentication required")
    limit(request, "ingest", digest(token), request.app.state.settings.ingest_limit)
    host = db.scalar(select(Endpoint).where(Endpoint.credential_digest == digest(token)).with_for_update())
    if host is None or host.revoked: raise HTTPException(401, "Endpoint credential is invalid or revoked")
    request.state.actor = f"endpoint:{host.id}"
    return host
