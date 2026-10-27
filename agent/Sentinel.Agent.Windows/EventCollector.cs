using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using System.Xml.Linq;
using Sentinel.Agent.Core;
namespace Sentinel.Agent.Windows;
public sealed class EventCollector(AgentOptions options,ProtectedFiles files,DurableBuffer journal) : IDisposable
{
    private sealed class ChannelState(LogChannel config) {public readonly object Gate=new();public readonly LogChannel Config=config;public EventLogWatcher? Watcher;public bool Paused;public EventHandler<EventRecordWrittenEventArgs>? Handler;}
    private readonly List<ChannelState> states=[];
    private readonly ConcurrentDictionary<string,CollectorHealth> health=new();
    private readonly object checkpointGate=new();
    private Dictionary<string,string> bookmarks=files.Exists("bookmarks.bin")?files.Read<Dictionary<string,string>>("bookmarks.bin"):[];
    private long expired;
    public long DrainExpired()=>Interlocked.Exchange(ref expired,0);
    public CollectorHealth[] Health=>health.Values.ToArray();
    public void Start(){foreach(var channel in options.EventChannels){var state=new ChannelState(channel);states.Add(state);Open(state);}}
    private void Open(ChannelState state)
    {
        EventLogWatcher? previous;
        lock(state.Gate){state.Paused=true;previous=state.Watcher;state.Watcher=null;}
        if(previous is not null){previous.EventRecordWritten-=state.Handler;previous.Dispose();}
        lock(state.Gate)
        {
            try
            {
                string? bookmark;lock(checkpointGate){bookmark=bookmarks.GetValueOrDefault(state.Config.Name);}
                var watcher=new EventLogWatcher(new EventLogQuery(state.Config.Name,PathType.LogName,state.Config.Query),bookmark is null?null:new EventBookmark(bookmark),bookmark is not null);
                state.Watcher=watcher;state.Paused=false;
                state.Handler=(_,args)=>Record(state,args);watcher.EventRecordWritten+=state.Handler;
                watcher.Enabled=true;health[state.Config.Name]=new("EventLog:"+state.Config.Name,"ready","Monitoring selected event IDs; raw XML and command lines are not transmitted.");
            }
            catch(EventLogException){state.Paused=true;health[state.Config.Name]=new("EventLog:"+state.Config.Name,"unavailable","Access denied, channel unavailable, or saved bookmark invalid; inspect the local event log and permissions.");}
        }
    }
    private void Record(ChannelState state,EventRecordWrittenEventArgs args)
    {
        using var record=args.EventRecord;
        if(record is null){health[state.Config.Name]=new("EventLog:"+state.Config.Name,"unavailable","Event subscription reported an error.");return;}
        lock(state.Gate)
        {
            if(state.Paused)return;
            try
            {
                var item=Parse(record.ToXml(),record.ProviderName??"",state.Config.Name,record.Id,record.RecordId??0,record.TimeCreated?.ToUniversalTime()??DateTime.UtcNow);
                if(DateTimeOffset.UtcNow-item.OccurredAt>TimeSpan.FromDays(6))
                {Interlocked.Increment(ref expired);health[state.Config.Name]=new("EventLog:"+state.Config.Name,"degraded","A record older than the six-day local retention policy was skipped.");}
                else if(!journal.TryAdd($"{item.OccurredAt.UtcTicks:D19}_{item.EventUid:N}",item))
                {
                    state.Paused=true;health[state.Config.Name]=new("EventLog:"+state.Config.Name,"paused","Protected event buffer is full; bookmark was not advanced.");
                    _=Task.Run(()=>{lock(state.Gate){if(state.Paused&&state.Watcher is not null)state.Watcher.Enabled=false;}});return;
                }
                lock(checkpointGate){bookmarks[state.Config.Name]=record.Bookmark.BookmarkXml;files.Write("bookmarks.bin",bookmarks);}
            }
            catch(Exception error)when(error is IOException or UnauthorizedAccessException or EventLogException or System.Security.Cryptography.CryptographicException or System.Xml.XmlException)
            {state.Paused=true;health[state.Config.Name]=new("EventLog:"+state.Config.Name,"unavailable","Record or protected checkpoint could not be persisted; collection paused.");}
        }
    }
    public void Resume(){foreach(var state in states.Where(s=>s.Paused).ToArray())if(journal.Count<options.MaxQueueFiles/4)Open(state);}
    public static AgentEvent Parse(string xml,string provider,string channel,int eventId,long recordId,DateTimeOffset time)
    {
        var doc=XDocument.Parse(xml);XNamespace ns="http://schemas.microsoft.com/win/2004/08/events/event";
        var data=doc.Descendants(ns+"Data").Where(x=>x.Attribute("Name") is not null).GroupBy(x=>x.Attribute("Name")!.Value).ToDictionary(g=>g.Key,g=>g.First().Value,StringComparer.OrdinalIgnoreCase);
        string Value(string key)=>data.GetValueOrDefault(key,"");
        var kind=eventId is 4624 or 4625?"authentication":eventId==7045?"persistence":eventId is 4688 or 4104?"process":"health";
        var image=Value("NewProcessName");var parent=Path.GetFileName(Value("ParentProcessName"));
        var command=eventId==4104?Value("ScriptBlockText"):Value("CommandLine");
        var signals=Signals.Process(Path.GetFileName(image),parent,image,command,"not_sampled").ToList();
        if(eventId==7045)signals.Add("service_created");
        if(eventId==4625)signals.Add("auth_failure");
        var details=new Dictionary<string,string>{{"channel",Wire.Bounded(channel,120)},{"record_id",recordId.ToString(System.Globalization.CultureInfo.InvariantCulture)},{"provider",Wire.Bounded(provider,200)}};
        if(!string.IsNullOrEmpty(image))details["image_path"]=Wire.Bounded(image,500);
        if(!string.IsNullOrEmpty(parent))details["parent_name"]=Wire.Bounded(parent,200);
        if(System.Net.IPAddress.TryParse(Value("IpAddress"),out var address))details["source_address"]=address.ToString();
        return new(Wire.StableId($"{channel}:{provider}:{recordId}:{time.UtcTicks}"),$"Windows event {eventId}","Windows EventLog:"+Wire.Bounded(channel,70),kind,time,"A real Windows event was collected. Review its ID, channel and derived context; raw event XML, account names and command lines are excluded.",eventId,signals.ToArray(),details);
    }
    public void Dispose(){foreach(var state in states){EventLogWatcher? watcher;lock(state.Gate){state.Paused=true;watcher=state.Watcher;state.Watcher=null;}watcher?.Dispose();}}
}
