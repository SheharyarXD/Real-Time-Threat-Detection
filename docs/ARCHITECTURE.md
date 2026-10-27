# Milestone 1 frontend architecture

## Scope and acceptance criteria

Implement and validate seven navigable frontend pages with simulated security data. The milestone ends before backend, authentication, agent development, or operational mitigation. The acceptance checklist is in MILESTONE-1.md.

## Stack and decisions

The supplied Sites starter pins Next.js 16.3.4, React/React DOM 19.2.6, TypeScript 5.9.3 and Tailwind CSS 4.2.1. The resolved lockfile selects Recharts 3.8.0, Lucide React 1.31.0, and Radix UI 1.6.7. Locally owned shadcn-style primitives provide accessible buttons and Radix dialogs. No remote fonts or image CDNs are required.

Sites uses Vinext 1.0.0-beta.5 and Vite 8.0.13 as its Next-compatible runtime adapter. This is a hosting-specific beta dependency, not a claim that Vinext is stable. The core frontend uses standard React, Next Link/usePathname, and TypeScript. For a conventional Next.js deployment, use the `dev:next` and `build:next` scripts; Sites builds use the supplied helpers. Both the conventional Next.js production build and the Sites build were verified.

Versions are mutually checked by TypeScript and the build; the supplied cached versions are retained for reproducibility rather than making unverified claims that every package is the latest. The lockfile is authoritative. TanStack Query is deferred until Milestone 2, when server state exists. There is no database, background job, or security API in this milestone.

## Project structure

| Path | Responsibility |
| --- | --- |
| `app/layout.tsx` | Metadata, global CSS, persistent client dashboard shell |
| `app/page.tsx` | Overview route |
| `app/[section]/page.tsx` | Validated section routes |
| `app/globals.css` | Dark design tokens, layout, severity styles, responsive breakpoints |
| `components/soc/soc-app.tsx` | Seven views, browser-session state, action orchestration, detail and confirmation flows |
| `components/soc/ui.tsx` | Panels, sortable/paginated tables, badges, search, meters, states, dialogs, switches |
| `components/soc/charts.tsx` | Recharts alert and resource visualizations |
| `components/ui/` | Starter shadcn component primitives |
| `lib/types.ts` | Platform-neutral entities, proposed API interface, realtime message envelope |
| `lib/mock-data.ts` | Explicitly fictional fixtures; reserved documentation address ranges |
| `lib/domain.ts` | Pure filtering, input guards, allowed status transitions, CSV escaping |
| `tests/domain.test.ts` | Automated tests of meaningful domain and export behavior |
| `docs/API-INTEGRATION.md` | Future integration routes, contracts, security boundaries |
| `docs/MILESTONE-1.md` | Acceptance evidence and limitations |
| `docs/MASTER-PROMPT.md` | Original supplied project specification |
| `scripts/`, `worker/`, `.openai/hosting.json` | Supplied Sites build and hosting adapter; not a security backend |

The small initial fixture set is handled in React state. The persistent root shell keeps the demo state across route navigation. Reloading resets it; no data or credentials are persisted. Future extraction of individual page components is straightforward as each view calls shared table, drawer, chart, form and status components.

## Design system

Dark canvas #101516; panel #171e20; borders #2b3639; text #e6eaea; muted text #92a0a3. Teal accents identify normal operation and navigation; pink identifies critical severity; amber identifies high severity and review; blue identifies medium severity; muted green identifies low severity. Labels accompany every color and status.

Desktop uses a fixed navigation rail, four summary cards, a trend/health grid and prioritized detections. Tablet uses two metric columns and stacked charts. At 820px the sidebar becomes a dismissible menu; smaller layouts preserve horizontally scrollable tables and wrap filters. Reduced-motion preferences disable animation. Radix dialogs handle focus trapping, escape dismissal, and restoration. Inputs have labels; tables have explicit sortable headers, keyboard-accessible detail buttons, pagination labels, and empty states. Global search supports Ctrl/Cmd+K.

## Safety boundaries

- A persistent banner labels simulated telemetry and response actions.
- Every creation, approval, rejection, retry, unblock, update, export, policy change, demo user addition and revocation is explicitly local-only.
- An approval transitions a valid request to **queued**, never directly to applied.
- “Applied” fixtures are labelled simulated; no observed firewall state exists.
- Protected management/essential ports, invalid addresses, wildcard/range scopes, revoked endpoints, duplicate active scopes, missing reasons and unbounded expiration are refused by the prototype.
- These client-side guards are UX previews, not security controls. Milestone 2/5 must repeat validation and authorization on the server and agent.
- Intelligence source records are samples. Update progress is an animation over fixtures; invalid-bundle mode retains the previous sample version.
