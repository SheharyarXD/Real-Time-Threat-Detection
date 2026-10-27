from pathlib import Path
from typing import Literal
from pydantic import SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[1]

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SENTINEL_", env_file=ROOT / ".env", extra="ignore")
    environment: Literal["development", "production", "test"] = "production"
    database_url: SecretStr
    session_secret: SecretStr
    allowed_origins: list[str] = ["http://127.0.0.1:3000", "http://localhost:3000"]
    allowed_hosts: list[str] = ["localhost", "127.0.0.1", "testserver"]
    session_hours: int = 8
    login_limit: int = 8
    request_limit: int = 240
    ingest_limit: int = 120
    stream_seconds: float = 1.0
    maximum_body_bytes: int = 1_048_576

    @model_validator(mode="after")
    def secure_configuration(self):
        secret=self.session_secret.get_secret_value()
        if len(secret) < 32 or secret.upper().startswith(("GENERATE_","REPLACE_","CHANGE_ME")):
            raise ValueError("A random session secret of at least 32 characters is required")
        if self.environment == "production":
            if not self.database_url.get_secret_value().startswith("postgresql+psycopg://"):
                raise ValueError("Production requires PostgreSQL with psycopg")
            if any(not origin.startswith("https://") for origin in self.allowed_origins):
                raise ValueError("Production browser origins must use HTTPS")
            if any("*" in host for host in self.allowed_hosts) or "testserver" in self.allowed_hosts:
                raise ValueError("Configure explicit production hostnames")
        return self

    @property
    def secure_cookie(self):
        return self.environment == "production"


def load_settings():
    from pydantic import ValidationError
    try: return Settings()
    except ValidationError:
        raise RuntimeError("Invalid backend configuration. Check required database URL, random session secret, and production HTTPS/hostname settings.") from None
