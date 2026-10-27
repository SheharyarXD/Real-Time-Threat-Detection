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
    title: str = Field(min_length=1, max_length=200)
    source: str = Field(min_length=1, max_length=100)
    event_type: Literal["authentication", "process", "file", "network", "vulnerability", "malware", "persistence", "health"]
    windows_event_id: int | None = Field(default=None, ge=0, le=65535)
    occurred_at: AwareDatetime
    evidence: str = Field(min_length=1, max_length=4096)

    @field_validator("occurred_at")
    @classmethod
    def bounded_time(cls, value):
        if not utcnow() - timedelta(days=7) <= value <= utcnow() + timedelta(minutes=5):
            raise ValueError("Event timestamp is outside the seven-day buffering window")
        return value
class Telemetry(StrictModel):
    batch_id: UUID
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
