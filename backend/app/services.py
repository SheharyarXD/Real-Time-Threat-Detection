import hashlib
import hmac
import json
import secrets
from datetime import timezone
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from fastapi import HTTPException
from sqlalchemy import select, func
from .models import AuditHead, AuditEvent, StreamHead, StreamEvent, Endpoint, SecurityEvent, Alert, utcnow

password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)
DUMMY_HASH = password_hasher.hash(secrets.token_urlsafe(24))
PROTECTED_PORTS = {22, 53, 88, 135, 389, 443, 445, 636, 3389, 5985, 5986}

def digest(value): return hashlib.sha256(value.encode()).hexdigest()
def new_token(): return secrets.token_urlsafe(32)
def aware(value): return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
def iso(value): return aware(value).isoformat() if value else None

def password_valid(password, hashed):
    try: return password_hasher.verify(hashed, password)
    except (VerificationError, InvalidHashError): return False

def csrf_token(raw_session, secret): return hmac.new(secret.encode(), f"csrf:{raw_session}".encode(), hashlib.sha256).hexdigest()

def audit_payload(sequence, created_at, actor, action, target, outcome, previous_hash):
    return json.dumps(dict(sequence=sequence, created_at=created_at, actor=actor, action=action, target=target, outcome=outcome, previous_hash=previous_hash), sort_keys=True, separators=(",", ":"))

def audit(db, actor, action, target, outcome="success"):
    head = db.scalar(select(AuditHead).where(AuditHead.id == 1).with_for_update())
    if head is None: raise RuntimeError("Audit head missing; run database migrations")
    timestamp = iso(utcnow())
    sequence = head.sequence + 1
    body = audit_payload(sequence, timestamp, str(actor), action, str(target), outcome, head.digest)
    item = AuditEvent(sequence=sequence, created_at=timestamp, actor=str(actor), action=action, target=str(target), outcome=outcome, previous_hash=head.digest, digest=digest(body))
    db.add(item)
    head.sequence, head.digest = sequence, item.digest
    db.flush()
    return item

def verify_audit(db):
    previous, sequence = "0" * 64, 0
    for row in db.scalars(select(AuditEvent).order_by(AuditEvent.sequence)):
        expected = digest(audit_payload(row.sequence, row.created_at, row.actor, row.action, row.target, row.outcome, row.previous_hash))
        if row.sequence != sequence + 1 or row.previous_hash != previous or not hmac.compare_digest(row.digest, expected): return False
        previous, sequence = row.digest, row.sequence
    head = db.get(AuditHead, 1)
    return head is not None and head.sequence == sequence and hmac.compare_digest(head.digest, previous)

def emit(db, event_type, data):
    head = db.scalar(select(StreamHead).where(StreamHead.id == 1).with_for_update())
    if head is None: raise RuntimeError("Stream head missing; run database migrations")
    head.sequence += 1
    db.add(StreamEvent(sequence=head.sequence, event_type=event_type, data=data))
    db.flush()

def endpoint_json(host,include_inventory=False):
    status = "revoked" if host.revoked else "offline" if not host.last_seen or (utcnow() - aware(host.last_seen)).total_seconds() > 120 else "degraded" if host.cpu > 85 or host.ram > 90 else "online"
    return dict(id=host.id, hostname=host.hostname, ip=host.ip, os=host.os, version=host.agent_version, group=host.group, status=status, cpu=host.cpu, ram=host.ram, disk=host.disk, networkBps=host.network_bps, lastSeen=iso(host.last_seen), origin=host.telemetry_origin,resourceObservedAt=iso(host.resource_observed_at),inventoryObservedAt=iso(host.inventory_observed_at),inventoryAvailable=host.inventory is not None,inventory=host.inventory if include_inventory else None,agentHealth=host.agent_health)

def event_json(event, alert=None):
    return dict(id=event.id, endpointId=event.endpoint_id, title=event.title, source=event.source, type=event.event_type, severity=event.severity, confidence=event.confidence, rule=event.rule, evidence=event.evidence, time=iso(event.occurred_at), receivedAt=iso(event.received_at), status=alert.status if alert else "recorded", origin=event.telemetry_origin, windowsEventId=event.windows_event_id,signals=event.signals or [],details=event.details or {})

def mitigation_json(item):
    return dict(id=item.id, endpointId=item.endpoint_id, protocol=item.protocol, port=item.port, direction=item.direction, address=item.address, reason=item.reason, status=item.status, expiresAt=iso(item.expires_at), requestedBy=item.requested_by, createdAt=iso(item.created_at), executionVerified=False)

def normalize(item,recent_failures=0):
    import re
    signals=set(item.signals)
    if "known_hash_indicator" in signals and re.fullmatch(r"[a-fA-F0-9]{64}",item.details.get("image_sha256","")) and item.details.get("rule_hash_source")=="operator_local_config": return "high",95,"HASH-M3-LOCAL: reported operator-configured hash match"
    if {"encoded_powershell","unusual_parent"}<=signals: return "high",85,"PROCESS-M3-ENCODED-PARENT: correlated reported process context"
    if {"temp_execution","unsigned_image"}<=signals: return "medium",60,"PROCESS-M3-TEMP-UNSIGNED: multiple reported execution signals"
    if "sensitive_file_changed" in signals: return "medium",70,"FIM-M3-CHANGE: selected baseline changed"
    if "persistence_registry_change" in signals: return "medium",70,"PERSIST-M3-RUN: startup-key baseline changed"
    if item.event_type=="authentication" and item.windows_event_id==4625 and recent_failures>=4: return "high",85,"AUTH-M3-BURST: five reported failed logons within two minutes"
    # M2 baseline classification, not a malware detector or proof of exploitation.
    if item.event_type == "authentication" and item.windows_event_id == 4625:
        return "medium", 70, "AUTH-BASELINE-4625: reported failed logon"
    if item.event_type == "persistence" and item.windows_event_id == 7045:
        return "medium", 60, "SERVICE-BASELINE-7045: reported service creation"
    return "low", 40, "TELEMETRY-BASELINE: uncorroborated reported event"

def page(db, statement, serializer, offset, limit):
    total = db.scalar(select(func.count()).select_from(statement.order_by(None).subquery()))
    records = db.scalars(statement.offset(offset).limit(limit)).all()
    return dict(items=[serializer(row) for row in records], total=total, cursor=str(offset + len(records)) if offset + len(records) < total else None)
