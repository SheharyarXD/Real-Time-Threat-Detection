using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sentinel.Agent.Core;
using Sentinel.Agent.Windows;
namespace Sentinel.Agent.Service;
public sealed class AgentWorker(AgentOptions options,ProtectedFiles files,AgentTransport transport,ILogger<AgentWorker> log) : BackgroundService
{
    private const string Version="0.3.0";
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var identity=files.Read<Identity>("identity.bin");
        var journal=new DurableBuffer(files,"journal",options.MaxQueueFiles/2,options.MaxQueueBytes/2);
        var outbox=new DurableBuffer(files,"outbox",options.MaxQueueFiles/2,options.MaxQueueBytes/2);
        using var eventLog=new EventCollector(options,files,journal);eventLog.Start();
        var sampler=new ResourceSampler();var signatures=new SignatureVerifier();var integrity=new FileIntegrityCollector(options,files,signatures);var inventoryCollector=new InventoryCollector(options,signatures);
        var health=new Dictionary<string,CollectorHealth>();DateTimeOffset inventoryAt=DateTimeOffset.MinValue,retryAt=DateTimeOffset.MinValue;bool suspended=false;int failures=0;long dropped=files.Exists("dropped.bin")?files.Read<long>("dropped.bin"):0;
        bool Journal(AgentEvent e)=>journal.TryAdd($"{e.OccurredAt.UtcTicks:D19}_{e.EventUid:N}",e);
        while(!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if(!suspended&&DateTimeOffset.UtcNow>=retryAt)
                {
                    foreach(var queued in outbox.Read<Envelope>(8))
                    {
                        if(DateTimeOffset.UtcNow-queued.Value.Payload.SampledAt>TimeSpan.FromDays(6))
                        {dropped+=queued.Value.Payload.Events.Length;outbox.Remove(queued.Name);log.LogWarning("Expired buffered batch removed under the six-day policy; batch={BatchId}",queued.Value.Payload.BatchId);continue;}
                        var result=await transport.Send(identity,queued.Value,stoppingToken);
                        if(result.Accepted)
                        {
                            foreach(var name in queued.Value.JournalNames)journal.Remove(name);
                            outbox.Remove(queued.Name);failures=0;health["Transport"]=new("Transport","ready","Last batch acknowledged by authenticated server.");
                        }
                        else
                        {
                            suspended=result.AuthorizationBlocked||result.Permanent;
                            health["Transport"]=new("Transport",suspended?"suspended":"retrying",suspended?"Server rejected credentials or payload; operator action is required. Buffered data is retained.":"Transient delivery failure; exact batch will be retried.");
                            retryAt=DateTimeOffset.UtcNow+AgentTransport.Backoff(++failures,result.RetrySeconds,.8+Random.Shared.NextDouble()*.4);break;
                        }
                    }
                }
                Inventory? inventory=null;
                if(DateTimeOffset.UtcNow>=inventoryAt)
                {
                    try
                    {
                        var result=inventoryCollector.Collect();inventory=result.Inventory;
                        foreach(var e in result.Events)if(!Journal(e))dropped++;
                        health["Inventory"]=new("Inventory",inventory.Truncated?"limited":"ready","Per-machine software, visible processes and services collected; raw command lines are not transmitted.");
                    }
                    catch(Exception error)when(error is System.Management.ManagementException or UnauthorizedAccessException or IOException)
                    {health["Inventory"]=new("Inventory","unavailable","Inventory permissions or WMI are unavailable.");}
                    try
                    {
                        bool persisted=true;foreach(var e in integrity.Collect())if(!Journal(e)){persisted=false;break;}
                        if(persisted){integrity.Commit();health["Integrity"]=new("Integrity",integrity.ScopeLimited?"limited":"ready",integrity.ScopeLimited?"Some selected files were reparse points or exceeded the 16 MiB hashing bound.":"Selected local file and startup-key baselines sampled.");}
                        else health["Integrity"]=new("Integrity","paused","Protected event buffer full; pending integrity change set retained.");
                    }
                    catch(Exception error)when(error is UnauthorizedAccessException or IOException or InvalidDataException)
                    {health["Integrity"]=new("Integrity","unavailable","Selected files, registry or protected baseline could not be read.");}
                    inventoryAt=DateTimeOffset.UtcNow.AddSeconds(options.InventoryIntervalSeconds);
                }
                var resources=sampler.Sample();var pending=journal.Read<AgentEvent>(50);
                foreach(var old in pending.Where(p=>DateTimeOffset.UtcNow-p.Value.OccurredAt>TimeSpan.FromDays(6))){journal.Remove(old.Name);dropped++;}
                pending=pending.Where(p=>DateTimeOffset.UtcNow-p.Value.OccurredAt<=TimeSpan.FromDays(6)).ToArray();
                var status=health.Values.Concat(eventLog.Health).Append(new CollectorHealth("Resources","ready","CPU/network use deltas; initial samples are warm-up baselines.")).ToArray();
                var payload=new Telemetry(Guid.NewGuid(),"agent",DateTimeOffset.UtcNow,resources,pending.Select(p=>p.Value).ToArray(),inventory,new(status,outbox.Count+journal.Count,dropped,Version));
                var envelope=new Envelope(identity.EndpointId,payload,pending.Select(p=>p.Name).ToArray());
                if(Wire.Encode(payload).Length>524288)throw new InvalidDataException("Telemetry exceeded the 512 KiB client bound; reduce collection scope.");
                if(outbox.TryAdd($"{payload.SampledAt.UtcTicks:D19}_{payload.BatchId:N}",envelope))foreach(var item in pending)journal.Remove(item.Name);
                else {dropped++;log.LogWarning("Protected outbox full; pending event records remain buffered, resource snapshot was not queued.");}
                dropped+=eventLog.DrainExpired();files.Write("dropped.bin",dropped);eventLog.Resume();
            }
            catch(OperationCanceledException)when(stoppingToken.IsCancellationRequested){break;}
            catch(Exception error)when(error is HttpRequestException or TaskCanceledException)
            {retryAt=DateTimeOffset.UtcNow+AgentTransport.Backoff(++failures);health["Transport"]=new("Transport","retrying","Network or TLS operation failed; certificate validation was not bypassed.");log.LogWarning("Telemetry delivery deferred; buffered batch retained.");}
            catch(Exception error)when(error is IOException or InvalidDataException or UnauthorizedAccessException or System.Text.Json.JsonException or System.Security.Cryptography.CryptographicException)
            {health["Agent"]=new("Agent","degraded","Local state, collection or payload bound failed; inspect the protected data directory.");log.LogError("Agent local-state operation failed; payloads and credentials were not logged.");}
            try{await Task.Delay(TimeSpan.FromSeconds(options.IntervalSeconds),stoppingToken);}catch(OperationCanceledException){break;}
        }
    }
}
