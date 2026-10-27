# Sentinel · Real-Time Threat Detection

A modular, Windows-first security operations platform built in six reviewable milestones.

**Current stage: Milestone 1, frontend prototype.** All telemetry, detections, intelligence content, and mitigation actions are simulated. There is no backend, operational authentication, Windows agent, external feed integration, or firewall enforcement. Do not use this prototype to monitor or protect a real host.

![Milestone 1 dashboard with simulated data](docs/dashboard-preview.jpg)

## Run locally

Use Node.js 22.13 or later and pnpm 11.25.0:

```bash
corepack enable
pnpm install --frozen-lockfile
pnpm dev
```

For npm users, `npm install` followed by `npm run dev` is also possible, but pnpm and the committed lockfile are the reproducible path. The development scripts use the supplied Sites Next-compatible Vinext runtime. For the standard Next runtime:

```bash
pnpm dev:next
pnpm build:next
```

Sites preview/deployment uses the supplied build integration. Both the standard Next.js build and the Sites build were verified.

## Validate

```bash
pnpm typecheck
pnpm test
pnpm build
```

The automated suite checks filters, request validation, protected ports, role restrictions, state transitions, and safe CSV encoding. Browser QA and known limitations are recorded in [Milestone 1](docs/MILESTONE-1.md).

## Explore

- `/` — summary metrics, severity trends, endpoint health, recent detections and response queue.
- `/endpoints` — inventory search, status filters, sorting, pagination, resource details and histories.
- `/threats` — severity cards, filters, evidence, confidence, related alerts and investigation status.
- `/mitigation` — bounded request forms, duplicate prevention, approvals, rejections, retries, unblocks and audit details.
- `/intelligence` — source provenance, sample versions, update/failure previews, scheduling and rollback configuration.
- `/logs` — event explorer, source/time filters, evidence and administrator CSV exports.
- `/administration` — users, role matrix, enrollment preview, revocation, policies and audit records.

Use **Prototype controls** to switch administrator/analyst personas or preview loading, empty, error and disconnected states. Ctrl/Cmd+K opens global search. All demo changes live in memory across route navigation and reset on reload. No invitation email is sent and no credential is generated.

## Structure and integration

Read [Architecture](docs/ARCHITECTURE.md), [API integration](docs/API-INTEGRATION.md) and the [Original specification](docs/MASTER-PROMPT.md). Shared components are in `components/soc`; pure domain guards are in `lib/domain.ts`; the proposed typed API and realtime contracts are in `lib/types.ts`.

## Milestones

| Milestone | Scope | Status |
| --- | --- | --- |
| 1 | Frontend dashboard and UX | Implemented; acceptance evidence in docs |
| 2 | Backend, authentication, enrollment | Awaiting Milestone 1 approval |
| 3 | Windows service agent | Not started |
| 4 | Intelligence and vulnerability integrations | Not started |
| 5 | Authenticated firewall response | Not started |
| 6 | Integration, hardening and release | Not started |

Each milestone is committed independently. Stop for review before starting the next milestone, as required by the supplied specification.

## Dependency notes

The supplied lockfile pins Next 16.3.4, React 19.2.6, TypeScript 5.9.3, Tailwind 4.2.1, Recharts 3.8.0, Lucide 1.31.0 and Radix UI 1.6.7. Sites uses Vinext 1.0.0-beta.5; this runtime adapter remains a beta dependency. TanStack Query is intentionally deferred until authenticated APIs exist in Milestone 2.
