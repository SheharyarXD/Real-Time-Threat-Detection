using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Sentinel.Agent.Core;

var cases=new List<(string Name,Func<Task> Run)>();
void Test(string name,Action run)=>cases.Add((name,()=>{run();return Task.CompletedTask;}));
void Check(bool value,string message="Assertion failed"){if(!value)throw new Exception(message);}
void Throws<T>(Action action)where T:Exception {try{action();}catch(T){return;}throw new Exception("Expected "+typeof(T).Name);}
var temporary=Path.Combine(Path.GetTempPath(),"sentinel-core-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(temporary);
AgentOptions Options(string url="https://soc.example.invalid")=>new(){ServerUrl=url,DataDirectory=temporary};
Telemetry Payload(Guid? id=null)=>new(id??Guid.NewGuid(),"agent",DateTimeOffset.UtcNow,new(1,2,3,4),[],null,new([],0,0,"0.3.0"));

Test("HTTPS is mandatory and HTTP exception is limited to loopback",()=>{Options().Validate();Throws<InvalidDataException>(()=>Options("http://soc.example.invalid").Validate());var o=Options("http://127.0.0.1:8000");Throws<InvalidDataException>(o.Validate);o.AllowHttpLoopbackDevelopment=true;o.Validate();o.ServerUrl="http://soc.example.invalid";Throws<InvalidDataException>(o.Validate);});
Test("Server origin cannot contain credentials, paths, fragments or queries",()=>{foreach(var url in new[]{"https://user:pass@example.invalid","https://example.invalid/api","https://example.invalid/?token=x","https://example.invalid/#x"})Throws<InvalidDataException>(()=>Options(url).Validate());});
Test("Collection and buffer configuration is bounded",()=>{var o=Options();o.IntervalSeconds=0;Throws<InvalidDataException>(o.Validate);o=Options();o.KnownBadHashes=["not-a-sha256"];Throws<InvalidDataException>(o.Validate);o=Options();o.ServiceName="name & command";Throws<InvalidDataException>(o.Validate);});
Test("Signature state alone never creates an actionable detection",()=>{Check(!Signals.Actionable(["unsigned_image"]));Check(!Signals.Actionable(["encoded_powershell"]));Check(Signals.Actionable(["temp_execution","unsigned_image"]));});
Test("Behavioral correlation still applies to trusted signatures",()=>{var s=Signals.Process("powershell.exe","w3wp.exe",@"C:\Windows\powershell.exe","-enc QUJDREVGR0g=","valid_cached_chain");Check(Signals.Actionable(s));Check(!s.Contains("unsigned_image"));});
Test("Execution-policy arguments do not match encoded-command rule",()=>{Check(!Signals.Process("powershell.exe","explorer.exe","", "-ExecutionPolicy RemoteSigned","not_sampled").Contains("encoded_powershell"));});
Test("Stable Windows event identities survive collection retries",()=>{Check(Wire.StableId("Application:Source:10:time")==Wire.StableId("Application:Source:10:time"));Check(Wire.StableId("Application:Source:10:time")!=Wire.StableId("Application:Source:10:other-time"));});
Test("Protected spool survives reopening, deduplicates and enforces quotas",()=>{
 var dir=Path.Combine(temporary,"spool");var protector=new TestProtector();var files=new ProtectedFiles(dir,protector);var buffer=new DurableBuffer(files,"journal",2,65536);var item=Payload();
 Check(buffer.TryAdd("one",item));Check(buffer.TryAdd("one",item));Check(buffer.Count==1);Throws<InvalidDataException>(()=>buffer.TryAdd("one",Payload()));
 var reopened=new DurableBuffer(new ProtectedFiles(dir,protector),"journal",2,65536);Check(reopened.Read<Telemetry>(1)[0].Value.BatchId==item.BatchId);Check(reopened.TryAdd("two",Payload()));Check(!reopened.TryAdd("three",Payload()));
 var contents=File.ReadAllBytes(Path.Combine(dir,"journal","one.bin"));Check(!Encoding.UTF8.GetString(contents).Contains("batch_id"));reopened.Remove(reopened.Read<Telemetry>(1)[0].Name);Check(reopened.Count==1);
});
Test("Protected records reject purpose substitution and path escape",()=>{var files=new ProtectedFiles(Path.Combine(temporary,"purposes"),new TestProtector());files.Write("one.bin",Payload());Throws<InvalidDataException>(()=>files.Write("../escape.bin",Payload()));File.Copy(Path.Combine(files.Root,"one.bin"),Path.Combine(files.Root,"two.bin"));Throws<CryptographicException>(()=>files.Read<Telemetry>("two.bin"));});
Test("Wire schema uses bounded protocol field names and preserves UUIDs",()=>{var p=Payload();var text=Encoding.UTF8.GetString(Wire.Encode(p));Check(text.Contains("\"batch_id\""));Check(text.Contains("\"sampled_at\""));Check(Wire.Decode<Telemetry>(Wire.Encode(p)).BatchId==p.BatchId);});
Test("Retry backoff honors bounded Retry-After and jitter",()=>{Check(AgentTransport.Backoff(1,120).TotalSeconds==120);Check(AgentTransport.Backoff(100,9999,1.2).TotalSeconds==300);Check(AgentTransport.Backoff(0,0,.8).TotalSeconds>=1);});
cases.Add(("Transport binds credentials and acknowledgments to endpoint and batch",async()=>{
 var p=Payload();var identity=new Identity(Guid.NewGuid(),new string('x',43),"https://example.invalid");var h=new FakeHandler(HttpStatusCode.Accepted,$"{{\"accepted\":true,\"batchId\":\"{p.BatchId}\"}}");using var client=new HttpClient(h);var transport=new AgentTransport(client,new("https://example.invalid"));
 Check((await transport.Send(identity,new(identity.EndpointId,p,[]),CancellationToken.None)).Accepted);Check(h.Authorization=="Bearer "+identity.AgentToken);Check(h.Target=="https://example.invalid/api/v1/agent/telemetry");
 try{await transport.Send(identity,new(Guid.NewGuid(),p,[]),CancellationToken.None);throw new Exception("Expected identity rejection");}catch(InvalidDataException){}
 try{await new AgentTransport(client,new("https://other.invalid")).Send(identity,new(identity.EndpointId,p,[]),CancellationToken.None);throw new Exception("Expected server binding rejection");}catch(InvalidDataException){}
 h.Body="{\"accepted\":true,\"batchId\":\""+Guid.NewGuid()+"\"}";try{await transport.Send(identity,new(identity.EndpointId,p,[]),CancellationToken.None);throw new Exception("Expected acknowledgment rejection");}catch(InvalidDataException){}
}));
cases.Add(("Unauthorized and invalid payload responses are not successful delivery",async()=>{var h=new FakeHandler(HttpStatusCode.Unauthorized,"{}");using var client=new HttpClient(h);var t=new AgentTransport(client,new("https://example.invalid"));var i=new Identity(Guid.NewGuid(),new string('x',43),"https://example.invalid");var e=new Envelope(i.EndpointId,Payload(),[]);Check((await t.Send(i,e,CancellationToken.None)).AuthorizationBlocked);h.Status=HttpStatusCode.UnprocessableEntity;Check((await t.Send(i,e,CancellationToken.None)).Permanent);h.Status=HttpStatusCode.TooManyRequests;Check(!(await t.Send(i,e,CancellationToken.None)).Permanent);}));
cases.Add(("Enrollment negotiates protocol 3 and binds the server origin",async()=>{
 var id=Guid.NewGuid();var token=new string('t',43);var h=new FakeHandler(HttpStatusCode.Created,$"{{\"endpointId\":\"{id}\",\"agentToken\":\"{token}\",\"protocolVersion\":3}}");using var client=new HttpClient(h);var t=new AgentTransport(client,new("https://example.invalid"));
 var identity=await t.Enroll(new(new string('e',43),"LAB","192.0.2.1","Windows fixture","0.3.0"),CancellationToken.None);Check(identity.EndpointId==id&&identity.ServerOrigin=="https://example.invalid");
 h.Body=h.Body.Replace("\"protocolVersion\":3","\"protocolVersion\":2");try{await t.Enroll(new(new string('e',43),"LAB","192.0.2.1","Windows fixture","0.3.0"),CancellationToken.None);throw new Exception("Expected protocol rejection");}catch(InvalidDataException){}
}));
Test("Retention expires batches by their oldest event, including freshly wrapped replay",()=>{
 var now=DateTimeOffset.UtcNow;var p=Payload();var oldEvent=new AgentEvent(Guid.NewGuid(),"Fixture","Fixture","health",now-TimeSpan.FromDays(6)-TimeSpan.FromSeconds(1),"Explicit test fixture");
 Check(!new Envelope(Guid.NewGuid(),p,[]).IsExpired(now));
 Check(new Envelope(Guid.NewGuid(),p with{Events=[oldEvent]},[]).IsExpired(now));
 Check(new Envelope(Guid.NewGuid(),p with{SampledAt=now-TimeSpan.FromDays(7)},[]).IsExpired(now));
});
int failed=0;
foreach(var test in cases){try{await test.Run();Console.WriteLine("PASS "+test.Name);}catch(Exception e){failed++;Console.Error.WriteLine("FAIL "+test.Name+": "+e.GetType().Name);}}
Directory.Delete(temporary,true);Console.WriteLine($"{cases.Count-failed}/{cases.Count} core tests passed.");return failed==0?0:1;

// Test-only authenticated encryption; the Windows service always uses DPAPI.
sealed class TestProtector : IDataProtector
{
 private readonly byte[] key=RandomNumberGenerator.GetBytes(32);
 public byte[] Protect(byte[] data,string purpose){var nonce=RandomNumberGenerator.GetBytes(12);var tag=new byte[16];var cipher=new byte[data.Length];using var aes=new AesGcm(key,16);aes.Encrypt(nonce,data,cipher,tag,Encoding.UTF8.GetBytes(purpose));return nonce.Concat(tag).Concat(cipher).ToArray();}
 public byte[] Unprotect(byte[] data,string purpose){var plain=new byte[data.Length-28];using var aes=new AesGcm(key,16);aes.Decrypt(data.AsSpan(0,12),data.AsSpan(28),data.AsSpan(12,16),plain,Encoding.UTF8.GetBytes(purpose));return plain;}
}
sealed class FakeHandler(HttpStatusCode status,string body):HttpMessageHandler
{
 public HttpStatusCode Status=status;public string Body=body;public string? Authorization;public string? Target;
 protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken cancellationToken){Authorization=request.Headers.Authorization?.ToString();Target=request.RequestUri?.ToString();return Task.FromResult(new HttpResponseMessage(Status){Content=new StringContent(Body)});}
}
