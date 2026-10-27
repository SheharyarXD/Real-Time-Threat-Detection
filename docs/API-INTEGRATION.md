# Planned API integration points

These are proposed contracts, not implemented HTTP endpoints. `lib/types.ts` defines `PlatformApi`, `Paginated<T>`, `EventFilters`, platform-neutral entities and `PlatformMessage`.

## Replace the fixtures

1. Implement `PlatformApi` against the FastAPI backend in Milestone 2.
2. Replace initial fixture state in `SocApp` with TanStack Query resources. Keep the same loading, empty, error and disconnected components.
3. Convert all mutation handlers to authenticated API mutations. Await the server response, refresh the relevant query, and surface rejected operations. Do not infer success from clicking a button.
4. Subscribe to the realtime endpoint; reconnect using sequence checkpoints and exponential backoff. Re-fetch authoritative state after a gap. Unsubscribe on unmount.
5. Remove demo persona switching in operational mode. Fetch user identity and permissions from an authenticated session. Enforce permissions in every API handler.

## Proposed routes

| Method / path | Frontend usage | Required authority |
| --- | --- | --- |
| `GET /api/v1/session` | Identity and effective permissions | Authenticated user |
| `GET /api/v1/endpoints?cursor=` | Inventory, health and summary | Analyst or administrator |
| `GET /api/v1/endpoints/{id}` | Endpoint drawer and histories | Analyst or administrator |
| `POST /api/v1/enrollments` | Short-lived enrollment grant | Administrator |
| `POST /api/v1/endpoints/{id}/revoke` | Revoke identity and pending work | Administrator |
| `GET /api/v1/events?severity=&endpoint=&type=&source=&from=&to=&q=&cursor=` | Detection feed and event explorer | Analyst or administrator |
| `GET /api/v1/events/{id}` | Evidence and correlated alerts | Analyst or administrator |
| `PATCH /api/v1/events/{id}` | Investigation status | Explicit investigation permission |
| `GET /api/v1/mitigations?status=&cursor=` | Response queue and history | Analyst or administrator |
| `POST /api/v1/mitigations` | Typed `MitigationInput` request | Administrator or explicit response policy |
| `POST /api/v1/mitigations/{id}/approve` | Approval with reason/version | Administrator |
| `POST /api/v1/mitigations/{id}/reject` | Rejection with reason | Administrator |
| `POST /api/v1/mitigations/{id}/revert` | Controlled rollback request | Administrator |
| `POST /api/v1/mitigations/{id}/retry` | Revalidate and retry failed work | Administrator |
| `GET /api/v1/intelligence` | Sources, versions and update status | Analyst or administrator |
| `POST /api/v1/intelligence/updates` | Returns asynchronous job ID | Administrator |
| `POST /api/v1/intelligence/versions/{id}/activate` | Validated rollback request | Administrator |
| `GET /api/v1/audit?cursor=` | Append-only audit explorer | Explicit audit permission |
| `POST /api/v1/exports` | Permission-checked, audited export job | Explicit export permission |
| `GET /api/v1/users`, `POST /api/v1/users` | Workspace accounts | Administrator |
| `GET/PATCH /api/v1/policies` | Detection and response configuration | Administrator for writes |
| `WSS /api/v1/stream` | Authenticated dashboard updates | Session-specific authorization |

## Data and errors

Proposed response: `{ items: T[], total: number, cursor?: string }`. Extend current fixture timestamps to complete ISO-8601 UTC strings at the transport boundary. Normalize installed products, CVE evidence, agent capabilities, connection timestamps and firewall observation timestamps in the backend rather than relying on display strings.

Proposed error: `{ code: string, message: string, requestId: string, fieldErrors?: Record<string,string> }`. Handle 401 by ending the session, 403 by hiding/rejecting actions, 409 by reloading stale state, 422 with field validation and 429 with bounded backoff. Never place raw event content into HTML. Use stable backend-generated identifiers; UI-generated demo IDs are not production command IDs.

## Commands and execution evidence

`MitigationInput` is a frontend proposal, not an executable command. The backend must add an authenticated requester, approved policy/version, endpoint binding, single-use request ID, issue/expiry timestamps, anti-replay data, signature and precise address/port semantics before delivery. Approval yields queued work. Only an authenticated agent result plus firewall-state reconciliation can yield applied. Reversion also requires verified execution before the UI reports completion.

Essential ports, management paths, remote administration, DNS and domain authentication need endpoint-specific protections; the prototype's static protected-port list is intentionally conservative and insufficient for production. Agent-offline actions remain queued and must expire. The frontend must never provide a shell string or arbitrary execution payload.

## Authentication, privacy and streaming

Use TLS, secure HttpOnly session cookies or another reviewed session mechanism, CSRF protection as applicable, server RBAC, ingestion limits, event size bounds and rate limits. Do not reuse the demo role switch as authentication. Endpoint enrollment must use independent revocable identities. Browser stream authorization must not accept an endpoint credential.

`PlatformMessage` carries `{ sequence, timestamp, type, data }` with endpoint, event, mitigation and connection variants. Add a versioned schema and validate every message at runtime before applying it. Query invalidation must reconcile the authoritative API state after reconnects or missed sequence numbers. Do not claim live connectivity until an authenticated backend heartbeat has been verified.

## Prototype caveats

The 24-hour, last-hour and 7-day choices are fixture views. Last-hour event filtering uses the fixture reference 14:32 UTC; all listed events are from the same day, so 24-hour and 7-day tables overlap. Trend buckets illustrate aggregate history independently of the 12 detailed recent-event fixtures. CPU/RAM charts are illustrative sample series, not collected observations. CSV exports contain only filtered fixture events, are labelled simulated and neutralize spreadsheet formula prefixes.

## Milestone 2 implementation

The original table above is the roadmap. M2 implements session/login/logout, users/deactivation, single-use enrollments/revocation, endpoint registration/revocation, inventory, normalized event ingestion/filtering/investigation status, persisted proposals, audit verification and authenticated SSE. `lib/backend-api.ts` defines connected response types; demo types/fixtures remain isolated.

Stream variants include `endpoint.changed`, `event.created`, `event.changed` and `mitigation.changed`. Records use full UTC ISO timestamps and UUIDs. Pagination uses `offset`/`limit` with a next-offset cursor. The fixed Next proxy deliberately excludes raw agent enrollment/ingestion routes.

Operational command approval/execution, intelligence updates, connected-record exports and editable detection policies remain future work. Their planned routes must not be confused with the working M2 API. See `backend/README.md` and `backend/app/main.py` for the current surface.
