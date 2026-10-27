# Milestone 2: backend, authentication and enrollment

Status: **implemented and validated for the local lab; awaiting review before Milestone 3**.

Date: 28 October 2026. Branch: `milestone-2-backend-auth-enrollment`. `main` and the Milestone 1 branch are preserved.

## Scope and architecture

The connected workspace flows through a fixed Next.js API proxy to FastAPI, SQLAlchemy transactions and PostgreSQL. Browser identities use server-side sessions, Argon2 password hashing, CSRF protection and server-enforced administrator/analyst permissions. Endpoint identities use single-use enrollment grants and independently revocable, high-entropy credentials. Hostnames and IP addresses are metadata, not authentication.

Telemetry is normalized and classified by a deliberately small server baseline, then stored as events and alerts. Operator proposals are persistent, bounded records; execution is disabled. Domain updates, audit entries and ordered stream events share database transactions. A database-backed SSE outbox supports reconnect cursors and session revalidation. A housekeeping worker expires unreviewed proposals and cleans expired rate/session records. PostgreSQL coordinates shared state; Redis is deferred for this MVP.

The original frontend remains a demo at `/`. `/live` has its own authentication flow and reads no fixture datasets. TanStack Query deduplicates backend fetches; stream notices refetch authoritative snapshots. Permissions come from the backend, and caches clear when sessions end. Loaded tables are explicitly limited to the latest 100 records; server pagination is available through offsets.

## Changed files

| Area | Files |
| --- | --- |
| Configuration and persistence | `backend/app/config.py`, `database.py`, `models.py`, `backend/requirements.lock`, `pyproject.toml` |
| Validation and security | `backend/app/schemas.py`, `security.py`, `middleware.py`, `services.py` |
| HTTP API, streaming and worker | `backend/app/main.py` |
| Migration | `backend/alembic/versions/0001_initial_authenticated_platform_schema.py`, Alembic config/environment/template |
| Operator setup | `backend/app/cli.py`, `backend/run.py`, `.env.example`, `compose.yaml`, `Dockerfile` |
| Connected frontend | `components/soc/live-workspace.tsx`, `dashboard-root.tsx`, `lib/backend-api.ts`, `app/live/page.tsx`, `app/api/v1/[...path]/route.ts` |
| Frontend integration | Root layout, demo-to-backend link, theme mappings, live layout styles, package and pnpm lockfile |
| Windows launchers | `start-platform.bat`, `start-backend.bat`, updated `scripts/start-dashboard.mjs` |
| Tests and docs | Backend API/SSE/proxy tests, updated launcher tests, backend/root READMEs, API notes and branch plan |

## Acceptance results

| Requirement | Result | Evidence |
| --- | --- | --- |
| Administrator authentication | Pass | Actual login, HttpOnly cookie, session lookup, expiry and logout tests; no default credentials |
| Server-side least privilege | Pass | Analyst writes and audit/account access rejected; investigation status permitted |
| CSRF and Origin checks | Pass | Missing/wrong CSRF and untrusted Origin rejected, including through the Next proxy |
| Enrollment | Pass | One-time 15-minute grants; expired/revoked/reused grants rejected; independent credentials for duplicate hostnames |
| Enrollment concurrency contract | Pass in PostgreSQL-compatible test server | Simultaneous consumers yield one 201 and one 401; native qualification remains outstanding |
| Credential revocation | Pass | Telemetry rejected after revocation; deactivated user sessions lose access |
| Validated ingestion | Pass | Credential-bound identity, forbidden extra identity/severity fields, bounded resources/timestamps/body size |
| Idempotency | Pass | Identical retries acknowledged once; changed content under the same batch ID rejected |
| Persistent alerts | Pass | Server baseline classifies lab 4625 reports and creates persistent alerts; filters/status changes verified |
| Inventory and health | Pass | Stored resources and last-seen status; unreported identities offline; revoked identities labelled |
| Mitigation records | Pass | Scoped proposals persist; protected services, broad targets, duplicate scopes and unbounded lifetimes refused; execution rejected |
| Housekeeping | Pass | Expired proposal, matching audit entry and stream event verified |
| Real-time updates | Pass | Actual HTTP SSE delivery, reconnect sequence and logout revocation tested |
| Complete frontend API boundary | Pass | Built Next server → proxy → FastAPI → database → proxied SSE; cookies, CSRF, enrollment, records and logout verified |
| Audit records | Pass | Authentication, enrollment, ingestion, account/proposal operations audited; changed chain record detected |
| PostgreSQL dialect and driver | Pass through PGlite/psycopg | Migration and complete 18-test suite pass through the PostgreSQL wire protocol |
| Local default tests | Pass | 17 backend tests on disposable SQLite; optional Next proxy test skipped in the default run |
| Existing domain/launcher suite | Pass | 19 Node tests |
| Frontend compilation | Pass | TypeScript, standard Next production build and Sites/Vinext build |
| Browser UI inspection | Partial | Sign-in, backend-unavailable error and demo link inspected; authenticated browser flow unavailable in preview |

The full suites contain **37 passing tests**: 19 Node and 18 backend tests, including the optional frontend proxy flow. The proxy test was enabled in the PostgreSQL-compatible run.

## Validation limits

Native PostgreSQL could not start because this environment exposes only a root UID and cannot create/switch to a PostgreSQL service user. Compatibility validation used PGlite 0.5.12 and pglite-socket 0.2.15, the actual psycopg driver and PostgreSQL dialect. The WASM server multiplexes connections and does not qualify native PostgreSQL multi-process concurrency, replication or performance. A native PostgreSQL lab run remains required before release.

The browser preview could serve the frontend but could not mount/run the Python virtual environment. Browser inspection therefore covers sign-in/error UI; authenticated end-to-end behavior is verified by the separate real HTTP Next/FastAPI test. No simulated connected-backend screenshot is used as evidence.

Native Windows batch execution, production TLS certificates/ingress, real Windows telemetry and firewall changes were not tested or deployed. Starlette warns that its TestClient httpx transport is deprecated; tests pass, and migration should be tracked before release.

SQLite is a disposable local test option and is rejected in production configuration. PGlite is a validation tool, not a deployed dependency. No test database, session secret, administrator password, token or populated `.env` file is committed. Audit hashing verifies records relative to the stored head; a database owner could rewrite the entire chain and head. External checkpoints/retention belong to Milestone 6.

## Selected versions

FastAPI 0.162.0, Uvicorn 0.54.0, SQLAlchemy 2.0.55, Alembic 1.20.1, psycopg 3.3.6, pydantic-settings 2.16.1, argon2-cffi 25.1.0. Frontend retains Next 16.3.4/React 19.2.6 and adds TanStack Query 5.104.5. Exact dependencies are pinned in lockfiles. Server prepared-statement caching is disabled for pool/multiplexer compatibility; SQL remains parameterized.

## Setup and checks

Use `start-platform.bat` after installing Python 3.12 and provisioning PostgreSQL. It opens backend setup in a separate terminal and starts the connected frontend. Manual setup, configuration, enrollment/ingestion, TLS expectations, backup and recovery notes are in `backend/README.md`.

```bash
# Frontend, repository root
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
pnpm build:next

# Backend, its virtual environment, from backend/
python -m alembic upgrade head
python -m app.cli create-user --role administrator
python -m pytest tests -q
```

For the optional proxy test, build Next first and set `SENTINEL_RUN_PROXY_TEST=1`. For PostgreSQL testing, set `SENTINEL_TEST_DATABASE_URL` to an isolated disposable database: tests drop/recreate that schema. Never use production data.

## Review boundary

Milestone 3 requires separate review and authorization. Planned branch: `milestone-3-windows-agent`. No Windows service, signed installer, intelligence-download service or remote firewall command implementation has started.
