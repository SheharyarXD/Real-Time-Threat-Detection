# Milestone 2 backend

FastAPI, SQLAlchemy, Alembic, PostgreSQL/psycopg, Argon2 password hashing, server-side browser sessions, independent endpoint credentials, and a persisted SSE event stream. A housekeeping task expires proposals and removes expired rate/session records. Redis is unnecessary for this lab MVP: shared temporary state and the ordered stream live in PostgreSQL.

No Windows service agent, intelligence fetch, executable command channel or firewall enforcement is implemented here. Lab telemetry must identify itself as `origin: "lab"`. The connected workspace starts empty; it never seeds the Milestone 1 fixtures.

## Windows setup

1. Install Python 3.12 with its launcher. Node.js setup is handled by the existing dashboard launcher.
2. Create a PostgreSQL database and database account with permission to run the supplied migrations. You may use PostgreSQL 16 locally or the Compose service below.
3. Double-click **`start-platform.bat`** in the repository root. In the backend window, complete database configuration and create the first administrator. Database URL and passwords are read through hidden terminal prompts. No default account or password exists.
4. The dashboard opens at **http://127.0.0.1:3000/live**. Sign in with the account you just created. If setup is still running, finish it in the backend window and retry sign-in.

The backend launcher creates a virtual environment, installs pinned packages when required, runs migrations, creates the first administrator if absent, and starts the API at http://127.0.0.1:8000. Keep both terminal windows open. Ctrl+C stops each service. Run `start-backend.bat --reinstall` to repair Python dependencies, or `start-dashboard.bat --connected --reinstall` to repair frontend dependencies.

Native Windows execution has not been verified in this Linux environment. If automatic Python discovery fails, install Python 3.12 from https://www.python.org/downloads/ or run `winget install --id Python.Python.3.12 --exact --source winget`, then reopen the launcher.

## Manual setup

Run these commands from `backend/`:

```bash
python -m venv .venv
# Windows:
.venv\Scripts\python -m pip install -r requirements.lock
.venv\Scripts\python -m app.cli init-config
.venv\Scripts\python -m alembic upgrade head
.venv\Scripts\python -m app.cli create-user --role administrator
.venv\Scripts\python -m uvicorn app.main:create_app --factory --host 127.0.0.1 --port 8000 --no-proxy-headers
```

On Linux/macOS use `.venv/bin/python` for the same commands. The configuration command creates `backend/.env` without overwriting an existing file. Provide a PostgreSQL URL in the form `postgresql+psycopg://USER:PASSWORD@127.0.0.1:5432/DATABASE`; URL-encode special characters in credentials. The session secret is generated locally. Keep `.env` private and outside source control.

In the repository root, copy `.env.example` to `.env.local` and run the standard Next.js frontend:

```bash
pnpm install --frozen-lockfile
pnpm dev:next
```

Open `/live`. The frontend proxies only its fixed browser API routes to `SENTINEL_API_URL`. It forwards only the Sentinel session cookie and required security headers; endpoint enrollment/ingestion routes are not exposed by that proxy.

## Optional local PostgreSQL container

Docker must already be installed. Copy `backend/.env.example` to `backend/.env`, replace its placeholders with unique local values, and set the matching `SENTINEL_DATABASE_URL`. Then, from `backend/`:

```bash
docker compose up -d postgres
```

The database port is bound to loopback and the data directory uses a named volume. `run.py` does not provision or delete a database automatically. The Compose service is a lab configuration, not a production deployment.

## Enrollment and ingestion contract

An administrator creates a 15-minute, single-use grant through `/live` or `POST /api/v1/enrollments`. The raw token is returned only at creation. The grant is bound to an enrollment identity, not an IP/hostname.

A future agent or authorized lab client sends:

```json
{
  "token": "THE_SINGLE_USE_ENROLLMENT_TOKEN",
  "hostname": "YOUR_AUTHORIZED_LAB_HOST",
  "ip": "YOUR_LAB_HOST_ADDRESS",
  "os": "YOUR_OPERATING_SYSTEM",
  "agent_version": "YOUR_CLIENT_VERSION"
}
```

to `POST /api/v1/agent/enroll`. The response contains a unique endpoint ID and an `agentToken` shown once. Save it in a protected endpoint credential store. Enrollment and agent credentials are hashed in the database. Revocation immediately prevents subsequent authenticated telemetry. Hosts are offline until an authenticated report arrives.

Telemetry is submitted to `POST /api/v1/agent/telemetry` with `Authorization: Bearer <agentToken>`. Payload fields are `batch_id` (UUID), `origin` (`lab` or `agent`), `resources` (`cpu`, `ram`, `disk`: 0–100; `network_bps`: nonnegative integer), and up to 100 `events`. Each event has `title`, `source`, `event_type`, optional `windows_event_id`, timezone-aware `occurred_at`, and `evidence`. See `/docs` in development or `app/schemas.py` for exact constraints. No password, token, endpoint ID override or agent-provided severity is accepted inside a telemetry batch.

Batch IDs are unique per endpoint. Identical retries are acknowledged without duplicate events; reusing an ID with different content returns 409. Event times are bounded to seven days of offline history and five minutes of future clock skew. Maximum request body is 1 MiB. A valid Windows 4625 or 7045 baseline report is classified medium and receives a persistent alert; other reports remain low-confidence, low-severity records. These baseline mappings are not a malware detector and do not prove exploitation. Detailed Windows detection belongs to Milestone 3.

## Sessions, permissions and streaming

- Browser sessions use random opaque tokens in HttpOnly, SameSite=Strict cookies, with Secure required in production. Only their SHA-256 digests are stored. Sessions expire after eight hours; logout and user deactivation revoke access.
- Browser mutations require an allowlisted Origin and an HMAC-derived CSRF header. Permissions are read from the database for every request. Analysts can read inventory/events and investigate alerts; administrators additionally manage accounts, enrollment, revocation, proposals and audit records.
- Persistent database rate buckets bound request, login and ingestion traffic across workers. Login hashing has a per-process concurrency limit. Configure ingress limits as part of production hardening.
- `/api/v1/stream` sends ordered `platform` events with `id`, sequence, ISO timestamp, type and data. It revalidates the session every poll. EventSource automatically reconnects with Last-Event-ID; callers may also use `?after=SEQUENCE`. A `session.expired` event ends unauthorized sessions. No database connection is held during the polling sleep.
- Stream sequence allocation is serialized in the same transaction as the domain mutation. This avoids a later-committed earlier sequence being silently skipped.
- Mutation audit records and stream records commit with the data change. Audit entries form a hash chain; `python -m app.cli verify-audit` verifies it relative to the current database head. This is not immutable storage: a database owner could rewrite the whole chain and head. External checkpoints and retention are Milestone 6 work.

## Local mitigations and future capabilities

The backend stores bounded, endpoint-scoped proposals with a single remote address, protocol, direction, local port, reason and expiry. Essential management/service ports are protected; duplicate active scopes are refused. An expiry task moves unreviewed proposals to expired. These are **review expirations**, not verified firewall-rule lifetimes. Every execution route rejects attempts until Milestone 5. Intelligence endpoints return `not_configured` until Milestone 4.

## Validation

```bash
# In the backend virtual environment:
python -m pytest tests -q
```

Default tests use disposable SQLite databases. To run against PostgreSQL, set `SENTINEL_TEST_DATABASE_URL` to an **isolated disposable test database**. The test fixture drops and recreates application tables in that database; never point it at production. The functional suite was also run through psycopg against PGlite's PostgreSQL WASM wire-protocol server. That validates the dialect and API contracts but does not qualify native PostgreSQL multi-process concurrency, replication or performance. Native PostgreSQL and Windows smoke tests remain required before a production release.

Tests cover authentication, origin/CSRF denial, analyst permissions, single-use/expired/revoked enrollment, credential hashing and revocation, idempotent telemetry and normalization, persistent alerts, proposal safeguards, audit tamper detection, login/body limits, TLS configuration, user deactivation, and real HTTP SSE delivery/reconnect/logout. The root Node test suite continues to cover the original frontend domain and launcher behavior.

## TLS and production

Development HTTP is for an authorized local lab only. Production configuration refuses insecure browser origins, weak/missing secrets, non-PostgreSQL storage and wildcard/test hostnames; production requests require an HTTPS scheme. Set `SENTINEL_ENVIRONMENT=production`, explicit HTTPS `SENTINEL_ALLOWED_ORIGINS`, and explicit `SENTINEL_ALLOWED_HOSTS`.

Use a TLS-terminating reverse proxy on the same host. Route `/api/v1/*` directly to the loopback FastAPI service and other paths to Next.js, preserving the original Host and HTTPS scheme. Start Uvicorn with `--host 127.0.0.1 --proxy-headers --forwarded-allow-ips 127.0.0.1` only when that reverse proxy is the trusted local ingress. Never trust forwarded headers from arbitrary clients. Keep PostgreSQL private; configure verified TLS for remote database connections and separate migration/runtime database roles.

No public backend, production TLS certificate, real agent or production firewall was deployed during this milestone.

## Backup and recovery

Before changing a populated schema, create a PostgreSQL custom-format backup with `pg_dump -Fc -f BACKUP_PATH DATABASE_NAME` using a protected credentials mechanism (password prompt, service file or OS-protected password file). Store backups separately from the host and test `pg_restore` into an isolated database. Never place passwords in command-line URLs or commit backups.

Restore the matching database backup and application revision together after a failed upgrade; take a new backup before any downgrade. `alembic downgrade base` is destructive and is only appropriate for disposable lab databases. Full disaster recovery and restore evidence are Milestone 6 deliverables.


## Milestone 3 agent protocol

Apply migration `0002` before using the Windows agent. Enrollment now includes `protocolVersion: 3`. Telemetry accepts optional `sampled_at`, bounded `inventory` and `health` objects, and per-event UUID `event_uid`, allowlisted `signals` and `details`. Responses bind accepted batches through `batchId`. Resource/inventory sample timestamps prevent delayed batches overwriting newer snapshots. Stable event IDs deduplicate cross-batch replay; changed content under the same ID is rejected transactionally with HTTP 409. Limits remain 1 MiB per request, 100 events per batch and 200 rows per inventory list. Agent requests are bounded further to 512 KiB/50 events.

`GET /api/v1/endpoints/{id}` includes full inventory; lists/stream updates include availability, observation timestamps and collector health without inventory rows. Event responses include signals/context and backend-assigned rule/severity. Command-line strings and raw XML are not valid context fields. The agent origin label is reported provenance from an authenticated endpoint, not a hardware attestation. Operator-local hash matches are labelled as such. Software vulnerability matching and intelligence integration remain Milestone 4. See [agent guide](../agent/README.md).
