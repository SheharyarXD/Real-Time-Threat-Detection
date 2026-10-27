from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint, Index, JSON
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

def utcnow(): return datetime.now(timezone.utc)
def identifier(): return str(uuid4())

class Base(DeclarativeBase): pass
class User(Base):
    __tablename__ = "users"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    username: Mapped[str] = mapped_column(String(100), unique=True)
    password_hash: Mapped[str] = mapped_column(Text)
    role: Mapped[str] = mapped_column(String(24))
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
class BrowserSession(Base):
    __tablename__ = "browser_sessions"
    digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
class Enrollment(Base):
    __tablename__ = "enrollments"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    digest: Mapped[str] = mapped_column(String(64), unique=True)
    label: Mapped[str] = mapped_column(String(120))
    group: Mapped[str] = mapped_column(String(100))
    created_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
class Endpoint(Base):
    __tablename__ = "endpoints"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    enrollment_id: Mapped[str] = mapped_column(ForeignKey("enrollments.id"), unique=True)
    credential_digest: Mapped[str] = mapped_column(String(64), unique=True)
    hostname: Mapped[str] = mapped_column(String(120))
    ip: Mapped[str] = mapped_column(String(45))
    os: Mapped[str] = mapped_column(String(200))
    agent_version: Mapped[str] = mapped_column(String(50))
    group: Mapped[str] = mapped_column(String(100))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cpu: Mapped[float] = mapped_column(Float, default=0)
    ram: Mapped[float] = mapped_column(Float, default=0)
    disk: Mapped[float] = mapped_column(Float, default=0)
    network_bps: Mapped[int] = mapped_column(Integer, default=0)
    telemetry_origin: Mapped[str] = mapped_column(String(12), default="unreported")
    resource_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    inventory_observed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    inventory: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    agent_health: Mapped[dict | None] = mapped_column(JSON, nullable=True)
class TelemetryBatch(Base):
    __tablename__ = "telemetry_batches"
    __table_args__ = (UniqueConstraint("endpoint_id", "batch_id"),)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    endpoint_id: Mapped[str] = mapped_column(ForeignKey("endpoints.id"), index=True)
    batch_id: Mapped[str] = mapped_column(String(36))
    payload_hash: Mapped[str] = mapped_column(String(64))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (Index("uq_endpoint_external_event", "endpoint_id", "external_id", unique=True),)
    external_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    external_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    signals: Mapped[list | None] = mapped_column(JSON, nullable=True)
    details: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    endpoint_id: Mapped[str] = mapped_column(ForeignKey("endpoints.id"), index=True)
    batch_id: Mapped[str] = mapped_column(ForeignKey("telemetry_batches.id"))
    title: Mapped[str] = mapped_column(String(200))
    source: Mapped[str] = mapped_column(String(100))
    event_type: Mapped[str] = mapped_column(String(32), index=True)
    windows_event_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    severity: Mapped[str] = mapped_column(String(12), index=True)
    confidence: Mapped[int] = mapped_column(Integer)
    rule: Mapped[str] = mapped_column(String(120))
    evidence: Mapped[str] = mapped_column(Text)
    telemetry_origin: Mapped[str] = mapped_column(String(12))
class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    event_id: Mapped[str] = mapped_column(ForeignKey("security_events.id"), unique=True)
    status: Mapped[str] = mapped_column(String(24), default="open")
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
class Mitigation(Base):
    __tablename__ = "mitigations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    endpoint_id: Mapped[str] = mapped_column(ForeignKey("endpoints.id"), index=True)
    requested_by: Mapped[str] = mapped_column(ForeignKey("users.id"))
    protocol: Mapped[str] = mapped_column(String(3))
    port: Mapped[int] = mapped_column(Integer)
    direction: Mapped[str] = mapped_column(String(8))
    address: Mapped[str] = mapped_column(String(45))
    reason: Mapped[str] = mapped_column(String(1000))
    status: Mapped[str] = mapped_column(String(24), default="pending approval")
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
class MitigationResult(Base):
    __tablename__ = "mitigation_results"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    mitigation_id: Mapped[str] = mapped_column(ForeignKey("mitigations.id"), index=True)
    result: Mapped[dict] = mapped_column(JSON)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
class FirewallObservation(Base):
    __tablename__ = "firewall_observations"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    endpoint_id: Mapped[str] = mapped_column(ForeignKey("endpoints.id"), index=True)
    state: Mapped[dict] = mapped_column(JSON)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
class IntelligenceSource(Base):
    __tablename__ = "intelligence_sources"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    attribution: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
class IntelligenceVersion(Base):
    __tablename__ = "intelligence_versions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    source_id: Mapped[str] = mapped_column(ForeignKey("intelligence_sources.id"))
    version: Mapped[str] = mapped_column(String(100))
    manifest_hash: Mapped[str] = mapped_column(String(64))
    active: Mapped[bool] = mapped_column(Boolean, default=False)
class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=identifier)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    content: Mapped[dict] = mapped_column(JSON)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
class StreamEvent(Base):
    __tablename__ = "stream_events"
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_type: Mapped[str] = mapped_column(String(32))
    data: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
class AuditHead(Base):
    __tablename__ = "audit_head"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sequence: Mapped[int] = mapped_column(Integer, default=0)
    digest: Mapped[str] = mapped_column(String(64), default="0" * 64)
class AuditEvent(Base):
    __tablename__ = "audit_events"
    sequence: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[str] = mapped_column(String(40))
    actor: Mapped[str] = mapped_column(String(120))
    action: Mapped[str] = mapped_column(String(100))
    target: Mapped[str] = mapped_column(String(150))
    outcome: Mapped[str] = mapped_column(String(40))
    previous_hash: Mapped[str] = mapped_column(String(64))
    digest: Mapped[str] = mapped_column(String(64), unique=True)
class RateBucket(Base):
    __tablename__ = "rate_buckets"
    key: Mapped[str] = mapped_column(String(160), primary_key=True)
    count: Mapped[int] = mapped_column(Integer)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
class StreamHead(Base):
    __tablename__ = "stream_head"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sequence: Mapped[int] = mapped_column(Integer, default=0)
