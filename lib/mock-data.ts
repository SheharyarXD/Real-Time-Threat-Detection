import type { Endpoint, SecurityEvent, Mitigation, AuditEvent, IntelligenceSource } from './types';
// All hosts, events, evidence, versions and actions in this file are fictional fixtures.
export const MOCK_AS_OF = '27 Oct 2026 · 14:32 UTC';
export const endpoints: Endpoint[] = [
 ['ep-01','WIN-DC-01','192.0.2.10','Windows Server 2022','online',28,62,41,'2.4 MB/s','8 sec ago','Domain controllers'],
 ['ep-02','WIN-WEB-02','192.0.2.21','Windows Server 2022','online',47,73,58,'8.1 MB/s','12 sec ago','Web servers'],
 ['ep-03','WIN-DB-01','192.0.2.30','Windows Server 2019','online',61,82,69,'4.7 MB/s','6 sec ago','Database servers'],
 ['ep-04','WIN-APP-03','192.0.2.43','Windows Server 2022','degraded',87,91,72,'1.2 MB/s','2 min ago','Application servers'],
 ['ep-05','WIN-FS-01','192.0.2.50','Windows Server 2019','online',19,44,81,'0.8 MB/s','18 sec ago','File servers'],
 ['ep-06','WIN-BACKUP-01','192.0.2.61','Windows Server 2022','offline',0,0,64,'0 MB/s','24 min ago','Infrastructure'],
 ['ep-07','WIN-WEB-01','192.0.2.20','Windows Server 2022','online',35,57,38,'5.3 MB/s','9 sec ago','Web servers'],
 ['ep-08','WIN-APP-01','192.0.2.41','Windows Server 2022','online',42,65,47,'2.1 MB/s','11 sec ago','Application servers'],
 ['ep-09','WIN-DC-02','192.0.2.11','Windows Server 2022','online',22,49,35,'1.9 MB/s','7 sec ago','Domain controllers'],
 ['ep-10','WIN-APP-02','192.0.2.42','Windows Server 2022','online',31,55,43,'2.6 MB/s','14 sec ago','Application servers'],
 ['ep-11','WIN-FS-02','192.0.2.51','Windows Server 2019','online',16,39,67,'0.5 MB/s','16 sec ago','File servers'],
 ['ep-12','WIN-MON-01','192.0.2.70','Windows Server 2022','online',24,48,52,'1.6 MB/s','10 sec ago','Infrastructure'],
].map((r,i)=>({id:r[0],hostname:r[1],ip:r[2],os:r[3],status:r[4],cpu:r[5],ram:r[6],disk:r[7],network:r[8],lastSeen:r[9],group:r[10],version:i===3?'0.8.2-demo':'0.9.0-demo'} as Endpoint));
export const events: SecurityEvent[] = [
 {id:'EVT-1048',title:'Repeated authentication failures',severity:'critical',endpointId:'ep-01',source:'Windows Security',type:'Authentication',time:'14:31:42',confidence:98,evidence:'38 failed logon events (4625) in 120 seconds for the lab account svc_backup from 198.51.100.24. No successful login is included in this fixture.',rule:'AUTH-004 · Brute-force threshold',status:'open'},
 {id:'EVT-1047',title:'Suspicious PowerShell execution',severity:'high',endpointId:'ep-02',source:'Process telemetry',type:'Process',time:'14:29:18',confidence:89,evidence:'Parent process w3wp.exe started powershell.exe with an encoded argument. Signature status: valid Microsoft publisher. The parent-child relationship requires investigation; signature validity alone does not imply safety.',rule:'PROC-012 · Unusual child process',status:'investigating'},
 {id:'EVT-1046',title:'Unusual outbound connection',severity:'high',endpointId:'ep-04',source:'Network telemetry',type:'Network',time:'14:27:05',confidence:87,evidence:'The lab application made 64 outbound TCP connections to 203.0.113.87:4444 in five minutes. The destination is a documentation-only address used for this example.',rule:'NET-008 · Connection frequency',status:'open'},
 {id:'EVT-1045',title:'Sensitive configuration file modified',severity:'medium',endpointId:'ep-02',source:'File integrity',type:'File integrity',time:'14:24:51',confidence:94,evidence:'A monitored IIS web.config file changed outside the sample maintenance window. Compare the approved baseline with the new file before taking action.',rule:'FIM-003 · Protected configuration',status:'open'},
 {id:'EVT-1044',title:'Software version requires review',severity:'medium',endpointId:'ep-03',source:'Software inventory',type:'Vulnerability',time:'14:21:37',confidence:76,evidence:'Inventory shows an outdated sample database component. This fixture is a vulnerability finding, not evidence of active exploitation. Confirm product identity and vendor guidance.',rule:'VULN-002 · Inventory correlation',status:'open'},
 {id:'EVT-1043',title:'Potentially unwanted startup entry',severity:'low',endpointId:'ep-08',source:'Registry monitoring',type:'Persistence',time:'14:18:12',confidence:65,evidence:'A new user-level Run entry references an unsigned utility in a temporary directory. Unsigned status alone does not establish malicious intent.',rule:'PERSIST-006 · Startup modification',status:'resolved'},
 {id:'EVT-1042',title:'Agent heartbeat delayed',severity:'medium',endpointId:'ep-06',source:'Agent health',type:'Health',time:'14:08:20',confidence:100,evidence:'The fixture endpoint has not reported for 24 minutes. Last acknowledged event sequence: 18312. Its displayed resources are last-known values.',rule:'HEALTH-001 · Missing heartbeat',status:'open'},
 {id:'EVT-1041',title:'Known test indicator matched',severity:'critical',endpointId:'ep-04',source:'Indicator match',type:'Malware',time:'13:58:04',confidence:96,evidence:'A fictional lab file hash matched the demo indicator set. No actual file was scanned, quarantined or executed. Review provenance and corroborating telemetry.',rule:'IOC-001 · File hash match',status:'investigating'},
 {id:'EVT-1040',title:'Unexpected service installation',severity:'high',endpointId:'ep-05',source:'Windows System',type:'Persistence',time:'13:46:10',confidence:84,evidence:'Windows event 7045 records a new service in the fictional lab. Service name: LabUpdater. Check the change record and binary publisher.',rule:'SVC-002 · New service',status:'open'},
 {id:'EVT-1039',title:'Administrator login outside baseline',severity:'low',endpointId:'ep-09',source:'Windows Security',type:'Authentication',time:'13:30:22',confidence:61,evidence:'Event 4624 for the lab admin account outside its fictional working-hour baseline. No additional suspicious activity is present in this fixture.',rule:'AUTH-008 · Login baseline',status:'resolved'},
 {id:'EVT-1038',title:'Disk utilization threshold exceeded',severity:'low',endpointId:'ep-05',source:'Agent health',type:'Health',time:'12:42:01',confidence:100,evidence:'Last-known disk utilization is 81%, exceeding the demonstration policy threshold of 80%.',rule:'HEALTH-004 · Storage capacity',status:'open'},
 {id:'EVT-1037',title:'Unusual DNS request volume',severity:'medium',endpointId:'ep-07',source:'Network telemetry',type:'Network',time:'11:12:49',confidence:72,evidence:'A sample host generated 240 DNS queries in 60 seconds. Review the process context and business workload before assigning a cause.',rule:'NET-011 · DNS baseline',status:'open'},
];
export const mitigations: Mitigation[] = [
 {id:'MIT-028',endpointId:'ep-01',protocol:'TCP',port:3389,direction:'Inbound',address:'198.51.100.24',reason:'Repeated authentication failures from a single lab source',status:'pending approval',expires:'1 hour',requestedBy:'Detection policy',eventId:'EVT-1048'},
 {id:'MIT-027',endpointId:'ep-04',protocol:'TCP',port:4444,direction:'Outbound',address:'203.0.113.87',reason:'Unusual outbound connections in fixture telemetry',status:'applied',expires:'30 minutes',requestedBy:'Alex Morgan',eventId:'EVT-1046'},
 {id:'MIT-026',endpointId:'ep-02',protocol:'TCP',port:8443,direction:'Inbound',address:'198.51.100.42',reason:'Example scoped inbound restriction',status:'applied',expires:'2 hours',requestedBy:'Alex Morgan'},
 {id:'MIT-025',endpointId:'ep-05',protocol:'UDP',port:5353,direction:'Outbound',address:'203.0.113.15',reason:'Example outbound investigation',status:'failed',expires:'30 minutes',requestedBy:'Alex Morgan'},
 {id:'MIT-024',endpointId:'ep-07',protocol:'TCP',port:8080,direction:'Inbound',address:'198.51.100.11',reason:'Completed sample investigation',status:'reverted',expires:'Expired',requestedBy:'Alex Morgan'},
 {id:'MIT-023',endpointId:'ep-08',protocol:'TCP',port:9000,direction:'Outbound',address:'203.0.113.12',reason:'Example time-bounded policy',status:'expired',expires:'Expired',requestedBy:'Detection policy'},
 {id:'MIT-022',endpointId:'ep-06',protocol:'TCP',port:4444,direction:'Outbound',address:'203.0.113.14',reason:'Awaiting sample endpoint connectivity',status:'queued',expires:'30 minutes',requestedBy:'Alex Morgan'},
];
export const auditEvents: AuditEvent[] = [
 {id:'AUD-910',time:'14:31:43',actor:'Detection policy',action:'Mitigation proposed',target:'MIT-028',outcome:'Awaiting approval'},
 {id:'AUD-909',time:'14:28:12',actor:'Alex Morgan',action:'Mitigation approved',target:'MIT-027',outcome:'Simulated applied'},
 {id:'AUD-908',time:'14:20:00',actor:'Update scheduler',action:'Intelligence version staged',target:'demo-2026.10.27',outcome:'Simulated validated'},
 {id:'AUD-907',time:'13:45:07',actor:'Alex Morgan',action:'Policy settings reviewed',target:'Default monitoring',outcome:'Recorded in fixture'},
 {id:'AUD-906',time:'13:30:11',actor:'Jamie Chen',action:'Investigation opened',target:'EVT-1047',outcome:'Read only'},
 {id:'AUD-905',time:'13:02:24',actor:'Alex Morgan',action:'Demo administrator session',target:'Dashboard',outcome:'Simulated login'},
];
export const intelligenceSources: IntelligenceSource[] = [
 {id:'urlhaus',name:'URLhaus',type:'Malicious URL indicators',count:'24,816',lastUpdate:'Today, 14:20',status:'validated',attribution:'abuse.ch · URLhaus'},
 {id:'threatfox',name:'ThreatFox',type:'Threat indicators',count:'18,402',lastUpdate:'Today, 14:20',status:'validated',attribution:'abuse.ch · ThreatFox'},
 {id:'yara',name:'Curated YARA rules',type:'File detection rules',count:'1,248',lastUpdate:'Today, 14:20',status:'validated',attribution:'Lab-curated sample bundle'},
 {id:'nvd',name:'NVD',type:'Vulnerability metadata',count:'38,726',lastUpdate:'Today, 14:20',status:'validated',attribution:'NIST · NVD'},
 {id:'malwarebazaar',name:'MalwareBazaar',type:'File hash metadata',count:'—',lastUpdate:'Yesterday, 14:20',status:'unavailable',attribution:'abuse.ch · MalwareBazaar'},
];
export const trend = [
 {time:'00:00',critical:1,high:4,medium:8,low:4},{time:'02:00',critical:0,high:3,medium:5,low:3},{time:'04:00',critical:1,high:2,medium:6,low:3},{time:'06:00',critical:0,high:4,medium:7,low:4},{time:'08:00',critical:1,high:5,medium:9,low:5},{time:'10:00',critical:0,high:4,medium:7,low:6},{time:'12:00',critical:2,high:7,medium:11,low:5},{time:'14:00',critical:2,high:8,medium:12,low:7},
];
