import type { NextRequest } from 'next/server';
export const dynamic = 'force-dynamic';
const paths=/^(session|auth\/(login|logout)|users(?:\/[a-f0-9-]+\/deactivate)?|enrollments(?:\/[a-f0-9-]+\/revoke)?|endpoints(?:\/[a-f0-9-]+(?:\/revoke)?)?|events(?:\/[a-f0-9-]+)?|mitigations(?:\/[a-f0-9-]+\/[a-z]+)?|audit(?:\/verify)?|intelligence|stream)$/;
async function proxy(request:NextRequest,{params}:{params:Promise<{path:string[]}>}){
 const {path}=await params;const joined=path.join('/');
 if(!paths.test(joined))return Response.json({message:'Unsupported dashboard API route'},{status:404});
 const base=process.env.SENTINEL_API_URL;
 if(!base)return Response.json({message:'Backend is not configured. Set SENTINEL_API_URL and start the FastAPI service.'},{status:503});
 let origin:URL;
 try{origin=new URL(base);if(!['http:','https:'].includes(origin.protocol)||origin.username||origin.password)throw Error('Invalid backend URL');}catch{return Response.json({message:'Invalid server backend configuration'},{status:503});}
 const headers=new Headers({Accept:request.headers.get('accept')??'application/json'});
 for(const name of ['content-type','origin','x-csrf-token','last-event-id']){const value=request.headers.get(name);if(value)headers.set(name,value);}
 const sessionCookie=request.cookies.get('sentinel_session');if(sessionCookie)headers.set('cookie',`sentinel_session=${sessionCookie.value}`);
 // Agent routes and arbitrary URLs are deliberately absent from this browser proxy.
 try{
  let body:ArrayBuffer|undefined;
  if(!['GET','HEAD'].includes(request.method)&&request.body){
   const reader=request.body.getReader();const chunks:Uint8Array[]=[];let length=0;
   while(true){const chunk=await reader.read();if(chunk.done)break;length+=chunk.value.length;if(length>1048576){await reader.cancel();return Response.json({message:'Request body exceeds 1 MiB'},{status:413});}chunks.push(chunk.value);}
   const combined=new Uint8Array(length);let offset=0;for(const chunk of chunks){combined.set(chunk,offset);offset+=chunk.length;}body=combined.buffer;
  }
  const result=await fetch(new URL(`/api/v1/${joined}${request.nextUrl.search}`,origin),{method:request.method,headers,body,cache:'no-store',redirect:'error',signal:request.signal});
  const outgoing=new Headers({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});
  for(const name of ['content-type','x-request-id','retry-after','x-accel-buffering']){const value=result.headers.get(name);if(value)outgoing.set(name,value);}
  for(const cookie of result.headers.getSetCookie())outgoing.append('set-cookie',cookie);
  return new Response(result.body,{status:result.status,headers:outgoing});
 }catch{return Response.json({message:'Backend connection is unavailable. Start the backend and check SENTINEL_API_URL.'},{status:503});}
}
export {proxy as GET,proxy as POST,proxy as PATCH};
