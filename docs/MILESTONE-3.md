# Milestone 3 · Windows endpoint monitoring

Branch: `milestone-3-windows-agent`, based on reviewed Milestone 2. Main and previous milestone branches remain unchanged. Milestone 4 has not started.

## Delivered

- .NET 10 Windows Worker Service with native resource counters, EventLogWatcher bookmarks, WMI process/service inventory, per-machine registry software inventory, selected-file and startup-key baselines, local Authenticode observations and explicit behavioral/hash rules.
- Single-use protocol 3 enrollment, bearer authentication over validated HTTPS, machine DPAPI records and restricted service/configuration ACLs. No arbitrary command channel or response enforcement.
- Bounded durable journals/outbox, immutable retry batches, acknowledgment binding, endpoint-bound identities, stable external event IDs, pending baseline recovery, backoff, collector health and quota/expiry visibility.
- Alembic migration `0002`: inventory, sample timestamps, agent health, event context and endpoint-scoped stable event identity. Older M2 telemetry payloads remain accepted; the new agent requires the M3 backend.
- Connected dashboard endpoint inventory, health, sample ages, provenance and detection evidence. Backend deduplicates replay and rejects reused IDs with different content. Delayed samples cannot overwrite newer observations.
- Windows build/install batch files, PowerShell service enrollment/lifecycle/recovery, local upgrade staging/rollback, hash manifest and optional certificate signing. Development installation is explicitly unsigned.

## Verified in this environment

| Check | Result |
| --- | --- |
| .NET service and native-test projects cross-compiled with warnings treated as errors | Pass, zero warnings/errors |
| Cross-platform agent core tests | 14 pass |
| Backend with PostgreSQL WASM through psycopg, including HTTP Next proxy/SSE | 22 pass |
| Existing domain/Windows launcher helper tests | 19 pass |
| TypeScript and standard Next production build | Pass |
| Native Windows collector checks | 10 pass on Windows CI |
| Native PostgreSQL backend CI | 21 pass, optional Next proxy test skipped |
| Actual Windows service/install/offline replay | Pending configuration compatibility rerun |
| Code-signing certificate, signed distribution/installer | Not available; optional signing path unverified |

PostgreSQL validation here uses PGlite's PostgreSQL engine and wire protocol, not native PostgreSQL performance testing. The Windows workflow additionally targets a native PostgreSQL service for backend checks. SQLite is used only for isolated Windows integration tests. A FastAPI test-client dependency deprecation warning remains; it does not affect test results.

## Acceptance limits

The source and Windows checks are implemented; native Windows behavior must be accepted only after the Windows CI job passes. Native collector execution passed on a Windows GitHub runner; the service integration rerun remains pending. Production TLS/proxy deployment, organizational audit policy, enterprise permissions, resource overhead, long-running retention and a signed MSI/distribution have not been certified. Inventory is bounded; signature checks are sampled and cached. The first integrity sample establishes a baseline. Software metadata prepares Milestone 4 vulnerability matching; no CVE or threat-feed status is invented.

See [agent operation and recovery](../agent/README.md) for exact collection caps, data fields, installation, retry behavior, publisher pinning and upgrade limitations. Review this milestone before continuing to threat intelligence.
