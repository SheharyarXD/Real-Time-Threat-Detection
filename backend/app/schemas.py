from datetime import timedelta
from typing import Literal
from uuid import UUID
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, AwareDatetime, field_validator
from .models import utcnow

class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
class Login(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=100, pattern=r"^[a-zA-Z0-9_.@-]+$")
    password: str = Field(min_length=1, max_length=256)
class UserInput(Login):
    password: str = Field(min_length=12, max_length=256)
    role: Literal["administrator", "analyst"]
class EnrollmentInput(StrictModel):
    label: str = Field(min_length=2, max_length=120)
    group: str = Field(default="Default", min_length=1, max_length=100)
class AgentEnrollment(StrictModel):
    token: str = Field(min_length=32, max_length=128)
    hostname: str = Field(min_length=1, max_length=120)
    ip: IPvAnyAddress
    os: str = Field(min_length=1, max_length=200)
    agent_version: str = Field(min_length=1, max_length=50)
class Resources(StrictModel):
    cpu: float = Field(ge=0, le=100, allow_inf_nan=False)
    ram: float = Field(ge=0, le=100, allow_inf_nan=False)
    disk: float = Field(ge=0, le=100, allow_inf_nan=False)
    network_bps: int = Field(ge=0, le=2**31-1)
class EventInput(StrictModel):
    event_uid: UUID | None = None
    signals: list[Literal["encoded_powershell","unusual_parent","temp_execution","unsigned_image","known_hash_indicator","sensitive_file_changed","persistence_registry_change","service_created","auth_failure"]] = Field(default_factory=list,max_length=16)
    details: dict[str,str] = Field(default_factory=dict,max_length=16)
    title: str = Field(min_length=1, max_length=200)
    source: str = Field(min_length=1, max_length=100)
    event_type: Literal["authentication", "process", "file", "network", "vulnerability", "malware", "persistence", "health"]
    windows_event_id: int | None = Field(default=None, ge=0, le=65535)
    occurred_at: AwareDatetime
    evidence: str = Field(min_length=1, max_length=4096)

    @field_validator("details")
    @classmethod
    def bounded_details(cls,value):
        allowed={"process_name","parent_name","image_path","signature_status","publisher","registry_key","file_path","prior_sha256","image_sha256","rule_hash_source","channel","record_id","provider","source_address"}
        if any(k not in allowed or len(v)>1024 for k,v in value.items()): raise ValueError("Event context field or length is not allowed")
        return value

    @field_validator("occurred_at")
    @classmethod
    def bounded_time(cls, value):
        if not utcnow() - timedelta(days=7) <= value <= utcnow() + timedelta(minutes=5):
            raise ValueError("Event timestamp is outside the seven-day buffering window")
        return value
class ProcessEntry(StrictModel):
    pid: int = Field(ge=0,le=2**31-1)
    name: str = Field(max_length=200)
    path: str = Field(max_length=500)
    parent: str = Field(max_length=200)
    signature: str = Field(max_length=100)
class ServiceEntry(StrictModel):
    name: str = Field(max_length=200)
    state: str = Field(max_length=40)
    start_mode: str = Field(max_length=40)
    image_path: str = Field(max_length=500)
class SoftwareEntry(StrictModel):
    name: str = Field(max_length=200)
    version: str = Field(max_length=100)
    publisher: str = Field(max_length=200)
class Inventory(StrictModel):
    processes: list[ProcessEntry] = Field(max_length=200)
    services: list[ServiceEntry] = Field(max_length=200)
    software: list[SoftwareEntry] = Field(max_length=200)
    truncated: bool
class CollectorHealth(StrictModel):
    name: str = Field(max_length=140)
    status: Literal["ready","limited","unavailable","paused","degraded","suspended","retrying"]
    message: str = Field(max_length=500)
class AgentHealth(StrictModel):
    collectors: list[CollectorHealth] = Field(max_length=24)
    queue_pending: int = Field(ge=0,le=200000)
    dropped_records: int = Field(ge=0,le=2**63-1)
    agent_version: str = Field(min_length=1,max_length=50,pattern=r"^[0-9A-Za-z.+_-]+$")
class Telemetry(StrictModel):
    batch_id: UUID
    sampled_at: AwareDatetime | None = None
    inventory: Inventory | None = None
    health: AgentHealth | None = None

    @field_validator("sampled_at")
    @classmethod
    def bounded_sample(cls,value):
        if value and not utcnow()-timedelta(days=7)<=value<=utcnow()+timedelta(minutes=5): raise ValueError("Sample timestamp is outside the buffering window")
        return value
    origin: Literal["lab", "agent"]
    resources: Resources
    events: list[EventInput] = Field(default_factory=list, max_length=100)
class EventStatus(StrictModel):
    status: Literal["open", "investigating", "resolved"]
class MitigationInput(StrictModel):
    endpoint_id: UUID
    protocol: Literal["TCP", "UDP"]
    port: int = Field(ge=1, le=65535)
    direction: Literal["Inbound", "Outbound"]
    address: IPvAnyAddress
    reason: str = Field(min_length=12, max_length=1000)
    ttl_minutes: Literal[15, 30, 60, 120] = 30
