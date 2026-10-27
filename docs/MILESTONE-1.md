# Milestone 1 acceptance

Status: **frontend acceptance passed; awaiting owner review before Milestone 2**.

Validation date: 27 October 2026. No operational detection or mitigation was implemented or tested.

## Scope delivered

Seven navigable views, a reusable SOC design system, fictional fixtures, shared session state, typed domain/API/realtime contracts, event and endpoint drawers, filtering/sorting/pagination, request confirmations, notifications, role previews, state previews, CSV export and integration documentation.

Changed application files: `app/layout.tsx`, `app/page.tsx`, `app/[section]/page.tsx`, `app/globals.css`, `components/soc/soc-app.tsx`, `components/soc/ui.tsx`, `components/soc/charts.tsx`, `lib/types.ts`, `lib/mock-data.ts`, `lib/domain.ts`, `public/favicon.svg`, `tests/domain.test.ts`, `package.json`, `tsconfig.json`, README and this docs directory. The supplied Sites adapter, selected shadcn primitives and their licenses are retained. Unused starter UI, database and example scaffolds were removed.

## Acceptance results

| Criterion | Result | Evidence |
| --- | --- | --- |
| Seven pages and navigation | Pass | Overview, Endpoints, Detection, Mitigation, Intelligence, Logs and Administration rendered in the browser; both builds resolve the route structure |
| Realistic, clearly labelled mock data | Pass | Persistent demo banner, sandbox sidebar, fixture timestamps, simulated action text; reserved documentation address ranges |
| Reusable UI | Pass | Shared panels, paginated sortable table, badges, meters, search, selects, dialog, drawer, state and chart components |
| Event filtering and evidence | Pass | Browser severity selection and evidence drawer; unit test combining query, severity, endpoint, type, source and time |
| Endpoint inventory | Pass | Search/status controls, resource columns, detail/history drawer; responsive inventory inspected |
| Safe request creation | Pass | Browser form created a bounded sample request; unit tests reject invalid ports, broad/invalid addresses, revoked identities and unbounded expiry |
| Approval and execution distinction | Pass | Browser approval produced **queued** and an audit entry; never inferred actual execution |
| Protected service handling | Pass | Browser approval of sample TCP 3389 request refused; automated protected-port tests |
| Role preview | Pass | Analyst persona disabled new requests, approvals, rejections, retries, unblocks, exports and administration writes |
| Audit continuity | Pass | Created/approved request visible after navigation to Administration → Audit trail |
| Intelligence update preview | Pass | Simulated update stages to demo version .2; invalid-bundle preview retained .2 and displayed failure |
| Loading/empty/error/disconnected states | Pass | Implemented state selector and state components; browser exercised error/reset and disconnected preview; empty search returned zero results |
| CSV export | Pass | Browser download inspected: simulated-data header, 12 records, evidence fields; unit test checks quoting and formula neutralization |
| Pagination | Pass | Browser event explorer moved from 1–6 to 7–12 with correct disabled next control |
| Responsive layout | Pass | Desktop screenshot, 768px tablet and 390px phone iframe viewports inspected; collapsed navigation and scrollable inventory |
| Typed integration points | Pass | `PlatformApi`, entity types, pagination and stream envelope; proposed routes, auth/error/reconnect boundaries in API-INTEGRATION.md |
| TypeScript | Pass | `pnpm typecheck` / `tsc --noEmit` |
| Automated behavior tests | Pass | 11 tests, 11 passed, 0 failed |
| Sites production build | Pass | Supplied build helper completed all five Vinext/Vite phases |
| Conventional Next.js build | Pass | Next 16.3.4 compiled, typechecked, generated pages and finalized successfully |

## Commands

```bash
corepack enable
pnpm install --frozen-lockfile
pnpm dev
pnpm typecheck
pnpm test
pnpm build
pnpm build:next
```

Browser QA was performed against the managed Sites preview. No Windows endpoint, production firewall or real intelligence source was contacted. Console inspection found browser-extension metadata errors; none were attributed to the application in the inspected records.

## Known limitations

- No real authentication or RBAC enforcement exists. Client role guards are only interaction previews.
- All records and actions are fixtures. Session changes survive route navigation but reset on refresh. No durable audit record, security service or real scheduler exists.
- Agent enrollment explains the future flow; it cannot create usable credentials or enroll a host. Demo users do not receive invitations.
- Approval only queues a sample request. There is no command transport, endpoint verification, execution acknowledgement or firewall reconciliation.
- The static protected-port list is conservative and cannot replace endpoint-specific production safety policy.
- Intelligence update progress, validation status, content counts, source provenance and rollback are illustrative. No cryptographic signature verification or licensing review has been integrated.
- Chart trend buckets and resource series illustrate history independently of the detailed recent-event fixtures. The seven-day table uses the same one-day sample set. Current timestamps are display fixtures, not live measurements.
- Sites uses a beta Vinext runtime adapter. A standard Next.js production build also passes, providing an independently checked portability path.
- Recharts is lazy loaded. Build tooling may still report a large chart vendor chunk; evaluate bundle optimization against real production usage in a later integration milestone.

## Review boundary

Review this milestone before starting Milestone 2. Backend APIs, database migrations, endpoint agents, threat-intelligence downloads and operational firewall controls are intentionally not started. This is the boundary required by Mandatory Development Rule 14 in the supplied master prompt.
