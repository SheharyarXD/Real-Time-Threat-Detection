import type { Endpoint, EventFilters, Mitigation, MitigationInput, MitigationStatus, Role, SecurityEvent } from './types.ts';
export const protectedPorts = [22,53,88,135,389,443,445,636,3389,5985,5986];
export function filterEvents(events: SecurityEvent[], filters: EventFilters): SecurityEvent[] {
 const query=(filters.query ?? '').toLowerCase();
 return events.filter(e => (!query || [e.title,e.id,e.evidence,e.source,e.type].join(' ').toLowerCase().includes(query)) && (!filters.severity || filters.severity==='all' || e.severity===filters.severity) && (!filters.endpoint || filters.endpoint==='all' || e.endpointId===filters.endpoint) && (!filters.type || filters.type==='all' || e.type===filters.type) && (!filters.source || filters.source==='all' || e.source===filters.source) && (filters.period!=='hour' || Number(e.time.slice(0,2))*60+Number(e.time.slice(3,5))>=13*60+32));
}
export function validateMitigation(input: MitigationInput, hosts: Endpoint[]): string | null {
 const host=hosts.find(e=>e.id===input.endpointId);
 if(!host || host.status==='revoked') return 'Choose an enrolled, non-revoked demo endpoint.';
 if(!['TCP','UDP'].includes(input.protocol) || !['Inbound','Outbound'].includes(input.direction)) return 'Choose a supported protocol and direction.';
 if(!Number.isInteger(input.port) || input.port<1 || input.port>65535) return 'Enter a port between 1 and 65535.';
 if(protectedPorts.includes(input.port)) return 'This port is protected for management or essential services. Choose a non-protected port for the demo.';
 const parts=input.address.trim().split('.');
 if(input.address!==input.address.trim() || parts.length!==4 || parts.some(x=>!/^(0|[1-9]\d{0,2})$/.test(x) || Number(x)>255) || ['0.0.0.0','255.255.255.255'].includes(input.address) || Number(parts[0])===0 || Number(parts[0])>=224) return 'Use a single valid unicast IPv4 address; broad scopes are not allowed.';
 if(input.reason.trim().length<12) return 'Add an investigation reason of at least 12 characters.';
 if(!['15 minutes','30 minutes','1 hour','2 hours'].includes(input.expires)) return 'Choose a bounded expiration.';
 return null;
}
export function nextMitigationStatus(item: Mitigation, action: 'approve'|'reject'|'revert'|'retry', role: Role): MitigationStatus {
 if(role!=='administrator') throw new Error('Administrator permission required.');
 if(action==='approve' && item.status==='pending approval') {
  if(protectedPorts.includes(item.port)) throw new Error('Protected service: this request requires a future management-safety policy. Approval is blocked in this prototype.');
  return 'queued';
 }
 if(action==='reject' && item.status==='pending approval') return 'rejected';
 if(action==='revert' && item.status==='applied') return 'reverted';
 if(action==='retry' && item.status==='failed') return 'queued';
 throw new Error('This action is not valid for the current request status.');
}
export function csv(rows: Record<string, unknown>[]): string {
 if(!rows.length) return '';
 const keys=Object.keys(rows[0]);
 const escape=(value: unknown)=>'"'+String(value??'').replace(/^[=+@\-\t\r]/,"'$&").replaceAll('"','""')+'"';
 return [keys.map(escape).join(','),...rows.map(row=>keys.map(key=>escape(row[key])).join(','))].join('\r\n');
}
