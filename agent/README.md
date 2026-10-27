# Windows monitoring agent · Milestone 3

C#/.NET 10 Worker Service, Windows x64. Intended lab targets: Windows Server 2019/2022/2025 and Windows 11. Native CI acceptance is tracked in [Milestone 3](../docs/MILESTONE-3.md); this is a development release until those checks pass. Build on Windows with .NET 10 SDK. The published package is self-contained; target machines do not need a separate .NET runtime. Use the **same milestone branch** for backend and agent: enrollment requires protocol version 3.

## Development setup

1. Start the migrated backend and connected dashboard using root `start-platform.bat`. PostgreSQL and Python 3.12 are backend prerequisites. For a remote agent, expose the backend through an operator-managed HTTPS reverse proxy with a certificate trusted by Windows. The agent connects to the FastAPI origin, not the dashboard's Next.js port. No certificate validation bypass is supported.
2. On a Windows build machine, run `agent/build-agent.bat`. It checks for the SDK and attempts WinGet installation when absent. The PowerShell build helper requires SDK major 10. If a different SDK is active, install/select .NET 10 and rerun. Output: `agent/artifacts/win-x64`, including a SHA-256 manifest.
3. In `/live`, sign in as an administrator and create a single-use enrollment token. It expires after 15 minutes. No password or reusable enrollment secret is shipped.
4. Open an elevated Windows PowerShell window. Run `agent/install-agent.bat` for the explicit **unsigned development** path. Enter the backend HTTPS origin and paste the token into the protected prompt. Tokens go through redirected stdin, never command-line arguments. The installer creates the service and protected configuration before enrollment. If enrollment fails, the service remains stopped; fix the issue and run `scripts/Enroll-Agent.ps1` with a fresh token if the previous one was consumed.
5. Open `/live` → Endpoints → endpoint details. Check provenance `agent`, resource sample time, inventory time, queue/drop counters and each collector's status. A successful subscription does not establish that Windows audit policy is enabled.

For same-host isolated testing only, PowerShell supports an explicit loopback HTTP exception:

```powershell
.\agent\scripts\Install-Agent.ps1 -ServerUrl 'http://127.0.0.1:8000' -AllowHttpLoopbackDevelopment -AllowUnsignedDevelopment
```

The service uses a virtual `NT SERVICE\SentinelAgent` identity, Event Log Readers membership, delayed automatic startup and SCM recovery (10/30/60 seconds). SYSTEM and administrators control binaries/configuration; only the service identity additionally modifies the state directory. Identity, bookmarks, baseline, change journal and outbox records use machine-scoped DPAPI plus restricted local ACLs. Local administrators remain trusted. State is bound to one endpoint ID and server configuration; do not copy an identity to another host or change its server origin. Revoke and enroll a fresh installation instead.

## Collection scope

- CPU and network rates use deltas; the initial sample is a warm-up baseline. RAM and system-drive used capacity are percentages. Default resource interval is 15 seconds.
- EventLogWatcher collects selected Security IDs 4624, 4625, 4688 and System ID 7045. Protected bookmarks advance only after durable journal writes. Security events require Windows audit policy and channel permissions. Configure approved policies separately; the installer does not change audit policy. Command-line auditing is optional and can expose secrets inside the local Windows event log; enable it only under your organization's policy.
- Every 300 seconds: visible processes, services and per-machine uninstall registry software entries. Each list is bounded to 200 entries with a truncation flag. The first 20 process images receive signature checks. Per-user/MSIX software, every transient process and catalogue-only signatures are not fully covered. `Win32_Product` is never invoked.
- File integrity defaults to the Windows hosts file. Set `file_integrity_paths` in the protected configuration to approved absolute files or directories. Directory scanning is **nonrecursive**, at most 1,000 files per selected directory; reparse points and files over 16 MiB are excluded and reported as limited. An unavailable file retains its previous baseline. Initial observations establish the baseline. HKLM Run/RunOnce values (32/64 bit) are hashed; raw registry command text is excluded. A pending change set is retained until durably journaled.
- Raw event XML, account names, command lines and file contents are not transmitted. Executable/file paths, software names, selected hashes, parent process names and authentication source addresses are transmitted and should follow your retention policy.

`config/agent.example.json` describes configuration; it contains placeholders, not a working server or credentials. Stop the service before changing its administrator-controlled configuration, validate it with `Sentinel.Agent.exe validate-config --config PATH`, then restart. The service cannot write its configuration or binaries. Do not loosen the DACL. No remote configuration or command-execution endpoint exists.

## Evidence and delivery

Backend rules combine encoded PowerShell with unusual parents, temporary-path execution with an unsigned embedded-signature observation, selected file/startup changes, explicitly configured SHA-256 indicators and five same-source failed logons within two minutes. Backend severity is recomputed. An unsigned image alone remains a low-severity observation; a valid signature never overrides behavioral evidence. WinVerifyTrust uses cached-chain/revocation information and labels unavailable/uncertain results. Publisher extraction is an observation, not a safety verdict. No online intelligence, CVE matching, quarantine, process termination or firewall mutation occurs.

The encrypted journal and immutable outbox each receive half of the configured disk/file budget (default total 128 MiB/10,000 files). Exact UUID batches retry with bounded exponential backoff and Retry-After (1–300 seconds). Server acknowledgment must name the submitted batch. Stable event IDs deduplicate replay across batches. Old observations cannot overwrite newer resources/inventory. Six-day-old buffered data expires within the backend's seven-day acceptance window; drop counters expose losses. File/resource sampling can be lost at a full quota; Event Log collection pauses without advancing its bookmark. Bounded buffering cannot promise unlimited retention. 401/403 and permanent payload errors suspend transport until an operator fixes the cause/restarts; credentials and queued data are retained and never silently replaced.

## Service lifecycle and recovery

Run these commands elevated; each verifies that the named service belongs to this installation:

```powershell
.\agent\scripts\Manage-Agent.ps1 -Action status
.\agent\scripts\Manage-Agent.ps1 -Action stop
.\agent\scripts\Manage-Agent.ps1 -Action start
.\agent\scripts\Manage-Agent.ps1 -Action uninstall
```

Uninstall removes the owned service/binaries and Event Log Readers membership, retaining protected state for review. Revoke the endpoint in the dashboard to invalidate server credentials. Reset/re-enrollment is a separate operator decision: archive/delete only the reviewed retained installation folder, then install with a fresh grant. The shared Application event source is retained. Use a custom `-ServiceName` for isolated parallel lab installations.

Inspect `Get-WinEvent -FilterHashtable @{LogName='Application';ProviderName='Sentinel.Agent'}` and `sc.exe qfailure SentinelAgent`. Log messages exclude credentials and telemetry bodies. Disk/DPAPI corruption, invalid bookmarks, denied channels and expired/revoked credentials require operator investigation. No automatic bookmark reset or credential overwrite is performed.

## Controlled release and upgrades

No signing certificate is included or provisioned. Unsigned development installation requires an explicit flag. For a release, use your organization's trusted code-signing certificate and approved timestamp server:

```powershell
.\agent\scripts\Build-Agent.ps1 -PublisherThumbprint '<trusted-certificate-thumbprint>' -TimestampServer '<approved-timestamp-url>'
.\agent\scripts\Install-Agent.ps1 -ServerUrl 'https://your-backend-origin' -PublisherThumbprint '<trusted-certificate-thumbprint>'
.\agent\scripts\Update-Agent.ps1 -PackagePath 'C:\ReviewedPackages\win-x64' -PublisherThumbprint '<trusted-certificate-thumbprint>'
```

The build signs the executable and a detached CMS manifest. Install/update verifies manifest signer and certificate chain, executable Authenticode publisher, all file hashes, duplicate/unlisted paths and reparse points. Establish the publisher pin through a separate trusted channel. The updater stages a **local operator-supplied package**, stops only the owned service, preserves configuration/state, keeps the previous binary directory and restores it if startup fails. Verify backend acknowledgment after any update; a running service alone is not a health check. Archive the previous release before another update. Publisher changes and signed-to-unsigned downgrades require a separately reviewed installation. There is no automatic downloader or remote updater. This repository supplies controlled scripts, not an MSI or a signed installer artifact; signing/distribution infrastructure remains a release prerequisite.

## Validation

```powershell
dotnet run --project agent/Sentinel.Agent.Tests -c Release
dotnet run --project agent/Sentinel.Agent.Windows.Tests -c Release
.\agent\scripts\Build-Agent.ps1
# Only on an isolated disposable elevated Windows CI runner:
.\agent\ci\Windows-Smoke.ps1
```

The Windows smoke test creates only its uniquely named test service, selected file, application event and disposable SQLite lab backend, then cleans up its state. It verifies actual enrollment, service execution, native collectors, Event Log subscription, FIM, offline/restart replay and uninstall. The GitHub Actions workflow runs it on Windows and runs protocol/backend tests against PostgreSQL separately. Do not upload state directories or tokens as build artifacts.
