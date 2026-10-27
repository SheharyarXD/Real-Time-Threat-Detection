export interface LiveSession {user:{id:string;username:string;role:'administrator'|'analyst'};csrfToken:string;}
export interface LiveInventory {processes:{pid:number;name:string;path:string;parent:string;signature:string}[];services:{name:string;state:string;start_mode:string;image_path:string}[];software:{name:string;version:string;publisher:string}[];truncated:boolean;}
export interface LiveAgentHealth {collectors:{name:string;status:string;message:string}[];queue_pending:number;dropped_records:number;agent_version:string;}
export interface LiveEndpoint {resourceObservedAt?:string|null;inventoryObservedAt?:string|null;inventoryAvailable?:boolean;inventory?:LiveInventory|null;agentHealth?:LiveAgentHealth|null;id:string;hostname:string;ip:string;os:string;version:string;group:string;status:string;cpu:number;ram:number;disk:number;networkBps:number;lastSeen:string|null;origin:'lab'|'agent'|'unreported';}
export interface LiveEvent {signals?:string[];details?:Record<string,string>;id:string;endpointId:string;title:string;source:string;type:string;severity:string;confidence:number;rule:string;evidence:string;time:string;receivedAt:string;status:string;origin:string;windowsEventId:number|null;}
export interface LiveAudit {id:string;time:string;actor:string;action:string;target:string;outcome:string;hash:string;}
export interface LiveMitigation {id:string;endpointId:string;protocol:string;port:number;direction:string;address:string;reason:string;status:string;expiresAt:string;executionVerified:boolean;}
export class ApiError extends Error {constructor(message:string,public status:number){super(message)}}
export async function backend<T>(path:string,method='GET',body?:unknown,csrf?:string):Promise<T>{
 const response=await fetch(`/api/v1/${path}`,{method,credentials:'same-origin',headers:{'Content-Type':'application/json',...(csrf?{'X-CSRF-Token':csrf}:{})},body:body===undefined?undefined:JSON.stringify(body),cache:'no-store'});
 const result=await response.json() as {message?:string};
 if(!response.ok)throw new ApiError(result.message??'Request failed',response.status);
 return result as T;
}
