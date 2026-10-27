export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type Role = 'administrator' | 'analyst';
export type ViewState = 'ready' | 'loading' | 'empty' | 'error' | 'disconnected';
export interface Endpoint { id: string; hostname: string; ip: string; os: string; version: string; status: 'online' | 'offline' | 'degraded' | 'revoked'; cpu: number; ram: number; disk: number; network: string; lastSeen: string; group: string; }
export interface SecurityEvent { id: string; title: string; severity: Severity; endpointId: string; source: string; type: string; time: string; confidence: number; evidence: string; rule: string; status: 'open' | 'investigating' | 'resolved'; }
export type MitigationStatus = 'pending approval' | 'queued' | 'applied' | 'failed' | 'expired' | 'reverted' | 'rejected';
export interface Mitigation { id: string; endpointId: string; protocol: 'TCP' | 'UDP'; port: number; direction: 'Inbound' | 'Outbound'; address: string; reason: string; status: MitigationStatus; expires: string; requestedBy: string; eventId?: string; }
export interface AuditEvent { id: string; time: string; actor: string; action: string; target: string; outcome: string; }
export interface IntelligenceSource { id: string; name: string; type: string; count: string; lastUpdate: string; status: 'validated' | 'review required' | 'unavailable'; attribution: string; }
export interface Paginated<T> { items: T[]; total: number; cursor?: string; }
export interface EventFilters { query?: string; severity?: string; endpoint?: string; type?: string; source?: string; period?: string; }
export interface MitigationInput { endpointId: string; protocol: 'TCP' | 'UDP'; port: number; direction: 'Inbound' | 'Outbound'; address: string; reason: string; expires: string; }
export interface PlatformApi {
  listEndpoints(signal?: AbortSignal): Promise<Paginated<Endpoint>>;
  listEvents(filters: EventFilters, signal?: AbortSignal): Promise<Paginated<SecurityEvent>>;
  listMitigations(signal?: AbortSignal): Promise<Paginated<Mitigation>>;
  requestMitigation(input: MitigationInput): Promise<Mitigation>;
  approveMitigation(id: string): Promise<Mitigation>;
  rejectMitigation(id: string, reason: string): Promise<Mitigation>;
  revertMitigation(id: string): Promise<Mitigation>;
  requestIntelligenceUpdate(): Promise<{ jobId: string }>;
  subscribe(listener: (event: PlatformMessage) => void): () => void;
}
export type PlatformMessage = { sequence: number; timestamp: string } & ({ type: 'endpoint.changed'; data: Endpoint } | { type: 'event.created'; data: SecurityEvent } | { type: 'mitigation.changed'; data: Mitigation } | { type: 'connection.changed'; data: { connected: boolean } });
