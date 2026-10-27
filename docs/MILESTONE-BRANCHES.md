# Milestone branches

Each milestone has its own branch, based on the reviewed previous milestone. Keep `main` and earlier snapshots intact until an explicit merge/release decision.

| Milestone | Branch | State |
| --- | --- | --- |
| 1 | `milestone-1-frontend` | Created; frontend and Windows launcher |
| 2 | `milestone-2-backend-auth-enrollment` | Created; authenticated backend and connected dashboard |
| 3 | `milestone-3-windows-agent` | Planned; not created or implemented |
| 4 | `milestone-4-threat-intelligence` | Planned; not created or implemented |
| 5 | `milestone-5-firewall-mitigation` | Planned; not created or implemented |
| 6 | `milestone-6-integration-hardening-release` | Planned; not created or implemented |

The supplied master prompt requires validation and review at each milestone boundary. Milestone 2 does not approve or start Milestone 3. Empty future branches are not presented as implemented work.

To review Milestone 2 in an existing Git clone:

```bash
git fetch origin
git switch milestone-2-backend-auth-enrollment
```

For GitHub ZIP downloads, select the milestone branch before downloading, then extract the complete repository.
