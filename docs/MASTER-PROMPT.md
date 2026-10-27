# Project: Real-Time Threat Detection and Automated Mitigation Platform

## Role and Objective

Act as a senior cybersecurity architect, SOC engineer, full-stack developer, Windows Server security specialist, and DevSecOps engineer.

Design and develop a production-oriented, modular **Real-Time Threat Detection and Automated Mitigation Platform**, initially targeting Windows Server environments, with an architecture that can support Linux endpoints in a later phase.

The platform must provide centralized endpoint monitoring, real-time security event collection, threat intelligence updates, vulnerability and suspicious activity detection, resource monitoring, and administrator-approved or policy-controlled automated mitigation.

The system should be inspired by the endpoint monitoring and detection capabilities of Wazuh, while implementing its own authenticated command-and-response mechanism for firewall mitigation.

Develop the platform in six milestones. Complete and validate each milestone before proceeding to the next. Do not build the entire application in one unstructured implementation.

---

## Milestone 1 — Frontend Dashboard and User Experience

**Priority: Build the complete frontend first.**

Create a professional, modern, intelligent, and visually polished cybersecurity dashboard. It should resemble a practical Security Operations Center (SOC) product rather than a generic admin template.

### Recommended frontend stack

- React with Next.js and TypeScript.
- Tailwind CSS for styling.
- shadcn/ui for consistent, accessible interface components.
- Recharts for security and resource visualizations.
- Lucide icons.
- TanStack Query for server-state management once APIs are connected.
- WebSocket-compatible frontend architecture for real-time events.

Use current stable, mutually compatible versions and document the selected versions.

### Dashboard design

Create a sophisticated but clean interface with a dark-first theme, restrained accent colors, readable typography, and clear security severity indicators. Support responsive desktop and tablet layouts.

Include these pages:

1. **Security Overview**
   - Total registered endpoints and online/offline status.
   - Critical, high, medium, and low severity alerts.
   - Threats detected today.
   - Active mitigations and blocked ports.
   - Endpoint health and connectivity.
   - Recent security events.
   - Threat and alert trends over time.

2. **Endpoints**
   - Endpoint hostname, IP address, operating system, agent version, and last-seen time.
   - CPU, RAM, disk, and network usage.
   - Agent health and connection status.
   - Endpoint details, event history, and mitigation history.
   - Search, filtering, and pagination.

3. **Threat Detection**
   - Suspicious process activity.
   - File integrity and suspicious file events.
   - Malware or potentially unwanted software detections.
   - Vulnerability findings.
   - Authentication anomalies and repeated failed logins.
   - Unusual network activity and relevant Windows security events.
   - Severity, detection source, evidence, timestamps, and confidence.

4. **Firewall and Mitigation Center**
   - Current mitigation actions.
   - Endpoint, affected protocol, port, direction, and reason.
   - Action status: pending approval, queued, applied, failed, expired, or reverted.
   - Manual block and unblock controls.
   - Administrator approval and rejection.
   - A visible audit trail for every action.
   - Clear warnings before disruptive firewall changes.

5. **Threat Intelligence and Signatures**
   - Last successful update.
   - Signature database version.
   - Number of indicators and rules available.
   - Update history and failures.
   - A manual **Update Threat Intelligence** button.
   - Scheduled update status.
   - Source attribution, timestamps, and signature validation status.

6. **Logs and Investigations**
   - Searchable, filterable event logs.
   - Severity, endpoint, event type, source, and time filters.
   - Event details with supporting evidence.
   - Related alerts and mitigation actions.
   - Export functionality subject to permissions.

7. **Administration and Audit**
   - User accounts and role-based access control.
   - Administrator and analyst roles.
   - Endpoint enrollment and revocation.
   - Detection policies and mitigation settings.
   - Audit history for login, configuration changes, approvals, and firewall operations.

### Frontend requirements

- Use realistic mock data only for the initial prototype.
- Clearly label simulated data; never present mock events as live detections.
- Build reusable components and a consistent design system.
- Include loading, empty, error, and disconnected states.
- Include realistic charts, tables, filters, detail drawers, confirmation dialogs, and notification messages.
- Keep navigation intuitive and avoid unnecessary complexity.
- Do not create fake backend functionality or claim that simulated mitigation has actually blocked a port.
- Define typed API interfaces so the frontend can connect to the real backend in later milestones.

**Milestone 1 deliverable:** A complete, navigable frontend with reusable components, mock-data support, responsive layouts, and documented API integration points.

---

## Milestone 2 — Backend, Authentication, and Endpoint Enrollment

Build the secure backend that connects the dashboard to endpoint agents.

### Recommended backend stack

- Python with FastAPI.
- PostgreSQL for persistent application data.
- SQLAlchemy and Alembic for database access and migrations.
- Redis where useful for temporary state, queues, and coordination.
- WebSockets or server-sent events for live dashboard updates.
- A background worker for scheduled jobs and asynchronous processing.

Choose a maintainable architecture that does not introduce unnecessary infrastructure during the initial MVP.

### Core backend capabilities

1. Secure administrator authentication.
2. Role-based access control with least-privilege permissions.
3. Endpoint enrollment and identity management.
4. Unique credentials and revocation for every endpoint.
5. Secure ingestion of endpoint telemetry.
6. Event normalization and severity classification.
7. Endpoint inventory and health status.
8. Persistent security event, alert, and mitigation records.
9. Real-time dashboard event delivery.
10. API validation, rate limiting, structured logging, and audit records.

### Secure communication

- Use TLS for agent-to-server and browser-to-server communication.
- Authenticate every endpoint independently.
- Do not trust an endpoint based solely on its IP address or hostname.
- Use IP allowlists as an additional control, not as the only authentication mechanism.
- Protect enrollment tokens and signing keys.
- Apply authorization checks to every sensitive API endpoint.
- Make command delivery authenticated, endpoint-specific, and auditable.

### Initial data model

Define appropriate entities for:

- Users and roles.
- Endpoints and enrollment credentials.
- Security events and alerts.
- Threat intelligence sources and versions.
- Detection rules and signatures.
- Mitigation requests and execution results.
- Firewall state observations.
- Audit events.

**Milestone 2 deliverable:** A working backend, database migrations, authenticated APIs, endpoint registration, and real-time event delivery.

---

## Milestone 3 — Windows Endpoint Agent and Real-Time Monitoring

Develop a lightweight Windows Server endpoint agent that can be installed as a signed Windows service.

The agent must register with the central platform and continuously send authorized telemetry to the dashboard.

### Agent requirements

1. Secure enrollment and authentication.
2. Hostname, operating system, IP address, and agent version reporting.
3. CPU, RAM, disk, and network utilization monitoring.
4. Windows Event Log collection using supported Windows interfaces.
5. Relevant Windows security and authentication event monitoring.
6. Process and service inventory.
7. File integrity monitoring for selected sensitive locations.
8. Installed software inventory and vulnerability assessment support.
9. Suspicious execution and persistence-related event collection.
10. Agent health reporting, retry logic, and offline buffering.
11. Secure configuration and controlled upgrades.
12. Windows Service installation, start, stop, uninstall, and recovery procedures.

### Threat detection

Implement a layered detection pipeline using:

- Explicit detection rules.
- File hashes and other threat indicators.
- File and publisher signature verification.
- Process and command-line context.
- Windows security events.
- File integrity changes.
- Software vulnerability data.
- Network and authentication anomalies.

Use Microsoft Authenticode and certificate-chain validation where appropriate to verify executable signatures.

**Important:** A valid digital signature does not prove that software is safe. An unsigned executable is not automatically malware. Combine multiple signals and explain the evidence behind every alert.

The agent should initially operate in monitoring mode. Do not quarantine files, terminate processes, or modify firewall settings solely because a heuristic score is high.

### Agent technology

Select the implementation language after considering Windows Service support, performance, packaging, maintainability, and secure update requirements. C#/.NET Worker Service is a suitable option for a Windows-first implementation.

Package the agent as a properly signed installer when signing infrastructure is available. Provide a controlled development-installation method for testing.

**Milestone 3 deliverable:** A functioning Windows endpoint agent reporting real host telemetry and security events to the dashboard.

---

## Milestone 4 — Threat Intelligence, Signatures, and Vulnerability Detection

Implement an extensible threat intelligence management service.

### Open-source intelligence sources

Evaluate reputable, actively maintained sources such as:

- abuse.ch URLhaus.
- abuse.ch ThreatFox.
- MalwareBazaar.
- YARA rules from trusted, maintained repositories.
- Official Microsoft security intelligence and vulnerability resources where applicable.
- NIST National Vulnerability Database (NVD) for vulnerability metadata.

Review each source's current availability, API requirements, licensing, rate limits, and redistribution conditions before integration.

Do not assume every source provides a downloadable antivirus signature database. Many provide indicators of compromise or threat metadata instead.

### Update workflow

Provide a dashboard button labelled **Update Threat Intelligence**.

When an authorized administrator activates it:

1. The backend validates the administrator's permissions.
2. The update service retrieves data from configured, trusted sources.
3. Responses are validated and normalized.
4. Indicators and rules are checked for format, duplication, freshness, and source provenance.
5. Signature files and rule bundles are validated before activation.
6. A new version is staged and integrity-checked.
7. The new version is atomically activated if validation succeeds.
8. The platform records the version, source, timestamp, item counts, and outcome.
9. Connected agents receive an authenticated notification that an approved update is available.
10. Agents download the approved update, verify its authenticity and integrity, and acknowledge the installed version.

Support scheduled updates, retry handling, rollback to the previous known-good version, and visible failure reporting.

### Integrity and trust

- Verify signed update manifests or bundles using a trusted signing key.
- Use cryptographic hashes to detect corruption.
- Use TLS for downloads.
- Never execute downloaded threat intelligence data as code.
- Never automatically trust an arbitrary third-party signature or rule repository.
- Scan or validate rules before activation.
- Keep source provenance and version history.

### Vulnerability assessment

Identify outdated software and known vulnerabilities by correlating installed software inventory with appropriate vulnerability databases.

Report the affected endpoint, product, version, CVE where applicable, severity, evidence, and remediation guidance.

Clearly distinguish a vulnerability finding from proof of active exploitation.

**Milestone 4 deliverable:** Functional intelligence updates, signature and rule versioning, validated deployment to agents, and vulnerability findings.

---

## Milestone 5 — Authenticated Command-and-Control and Firewall Mitigation

Implement the central mitigation workflow that allows the dashboard to request a specific endpoint action and verify its result.

This is a defensive, administrator-controlled response system for explicitly enrolled and authorized endpoints.

### End-to-end workflow

1. The detection engine identifies suspicious activity.
2. The platform creates an alert with supporting evidence and a severity score.
3. A response policy determines whether the event requires notification, manual approval, or a narrowly defined automatic action.
4. The platform creates a mitigation request containing the endpoint identity, protocol, port, direction, reason, expiration policy, and unique request ID.
5. The endpoint receives the request through an authenticated communication channel.
6. The agent validates the request's signature or authenticated origin, endpoint binding, freshness, authorization, and policy constraints.
7. The agent applies the permitted firewall change using supported Windows Firewall interfaces.
8. The agent reports the actual execution result and resulting firewall state.
9. The backend updates the dashboard only after receiving evidence of execution.
10. An administrator can review the action and request a controlled unblock or rollback.

### Firewall controls

Support:

- TCP and UDP rules.
- Specific local or remote ports as appropriate.
- Inbound and outbound direction.
- Narrowly scoped source and destination addresses when needed.
- Endpoint-specific firewall actions.
- Rule expiration and automatic review.
- Manual unblock and rollback.
- Conflict detection and duplicate-rule prevention.
- Current firewall-state reconciliation.
- Failed-action reporting and retries.

Do not blindly disable an entire service or block all traffic to an endpoint. Avoid broad firewall changes that could interrupt remote administration, DNS, domain authentication, monitoring, or business-critical services.

Implement safeguards against locking administrators out of remote servers. Use protected management rules, bounded actions, staged deployment, and a recovery procedure.

### Approval model

Provide two configurable response modes:

**Mode A — Approval required:** The dashboard raises an alert and queues the proposed firewall action. An authorized administrator reviews the evidence and approves or rejects the request.

**Mode B — Policy-authorized automation:** The platform automatically applies only explicitly configured, narrowly scoped response actions for qualifying detections. High-impact or uncertain actions require manual approval.

The platform must never bypass the endpoint's authorization checks just because a request originates from the dashboard.

### Command security

- Use mutual TLS or an equivalent authenticated channel.
- Use signed, time-limited commands or authenticated messages.
- Include unique request IDs and anti-replay protections.
- Enforce endpoint binding and command allowlists.
- Apply least privilege to the endpoint's firewall operations.
- Record the requesting user, approval, reason, command, response, and final state.
- Reject malformed, expired, duplicated, or unauthorized requests.
- Implement revocation and emergency suspension of remote actions.

The agent should not expose an arbitrary remote shell or unrestricted command-execution interface. The central platform should issue only structured, explicitly supported response actions.

**Milestone 5 deliverable:** Verified end-to-end detection-to-mitigation workflows, real Windows Firewall enforcement, administrator approval, safe rollback, and complete audit history.

---

## Milestone 6 — Integration, Hardening, Testing, and Release

Integrate all milestones into a complete working product.

### Testing

Provide automated and manual tests for:

- Administrator authentication and permissions.
- Endpoint enrollment and credential revocation.
- Real-time telemetry ingestion.
- Threat event detection.
- Intelligence updates and invalid bundles.
- Signature and rule verification.
- Authenticated command delivery.
- Replay and unauthorized command rejection.
- Firewall rule creation and removal.
- Expired and duplicate mitigation requests.
- Agent offline and reconnect behavior.
- Backend and database failures.
- Audit trail completeness.
- Resource usage and endpoint performance.
- Agent update integrity and rollback.

Run mitigation tests only on dedicated lab systems or other explicitly authorized test endpoints. Verify firewall rules and connectivity before, during, and after each test.

### Deployment

Provide:

- Backend deployment instructions.
- PostgreSQL setup and backup procedures.
- Dashboard deployment.
- Windows agent installer and enrollment guide.
- TLS certificate setup.
- Firewall and network requirements.
- Environment-variable templates without real secrets.
- Database migration instructions.
- Logging and troubleshooting guidance.
- Secure update and recovery procedures.
- Backup, restore, and disaster-recovery procedures.

Use Docker Compose for suitable development services if helpful. Do not require Kubernetes for the initial MVP.

### Security hardening

- Keep credentials and private keys outside source control.
- Apply least-privilege service accounts.
- Secure the dashboard and backend with TLS.
- Rate-limit sensitive endpoints.
- Validate and sanitize incoming event data.
- Protect against SQL injection, cross-site scripting, cross-site request forgery where relevant, and broken access control.
- Track dependencies and security advisories.
- Maintain immutable or tamper-evident audit records where feasible.
- Define retention and privacy policies for endpoint telemetry.
- Document incident response and recovery procedures.

### Linux extension readiness

Keep the event schema, agent communication protocol, detection pipeline, and mitigation request model platform-neutral where possible.

In a future Linux milestone, implement a dedicated Linux agent and use supported host firewall mechanisms such as nftables. Do not attempt to reuse Windows-specific firewall commands on Linux.

**Milestone 6 deliverable:** A fully integrated MVP with reproducible deployment, test evidence, security documentation, recovery instructions, and a documented path to Linux support.

---

## Mandatory Development Rules

1. Work strictly in milestone order, starting with the frontend.
2. At the start of each milestone, explain the scope, architecture, files, and acceptance criteria.
3. Implement complete, runnable files rather than isolated snippets whenever practical.
4. Maintain a clear project structure and consistent naming conventions.
5. Keep secrets, configuration, and business logic separated.
6. Include validation, error handling, logging, and automated tests.
7. Do not mark a feature complete until it has been implemented and tested.
8. Clearly identify simulated features versus operational security controls.
9. Do not hardcode IP addresses, passwords, tokens, or cryptographic secrets.
10. Do not deploy destructive mitigation behavior to production by default.
11. Keep the MVP practical for a small development team and a Windows Server lab.
12. Document important technical decisions and explain them in beginner-friendly language.
13. After completing each milestone, provide a summary, changed files, setup commands, tests performed, known limitations, and explicit acceptance results.
14. Stop at each milestone boundary and wait for approval before beginning the next milestone.
15. Never claim real-time detection, successful threat intelligence updates, or actual firewall mitigation unless the relevant integration has been implemented and its behavior verified.

## Start Now

Begin with **Milestone 1 only**.

First, present the frontend architecture, recommended project folder structure, component plan, page list, design system, and installation commands. Then implement the complete dashboard frontend using realistic but clearly labelled mock data.

Do not start backend development or endpoint-agent implementation until Milestone 1 has been reviewed and approved.
