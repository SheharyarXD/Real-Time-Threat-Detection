using System.Text.Json;
using System.Text.Json.Serialization;
namespace Sentinel.Agent.Core;

public static class Wire
{
    public static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower, PropertyNameCaseInsensitive = true, DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull };
    public static byte[] Encode<T>(T value) => JsonSerializer.SerializeToUtf8Bytes(value, Json);
    public static T Decode<T>(byte[] value) => JsonSerializer.Deserialize<T>(value, Json) ?? throw new InvalidDataException("Empty protected record.");
    public static Guid StableId(string value) => new(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value)).AsSpan(0,16));
    public static string Bounded(string? value, int max = 256) => string.IsNullOrEmpty(value) ? "" : value[..Math.Min(value.Length,max)];
}
public sealed record Resources(double Cpu, double Ram, double Disk, int NetworkBps);
public sealed record AgentEvent(Guid EventUid, string Title, string Source, string EventType, DateTimeOffset OccurredAt, string Evidence, int? WindowsEventId = null, string[]? Signals = null, Dictionary<string,string>? Details = null);
public sealed record CollectorHealth(string Name, string Status, string Message);
public sealed record ProcessEntry(int Pid, string Name, string Path, string Parent, string Signature);
public sealed record ServiceEntry(string Name, string State, string StartMode, string ImagePath);
public sealed record SoftwareEntry(string Name, string Version, string Publisher);
public sealed record Inventory(ProcessEntry[] Processes, ServiceEntry[] Services, SoftwareEntry[] Software, bool Truncated);
public sealed record AgentHealth(CollectorHealth[] Collectors, int QueuePending, long DroppedRecords, string AgentVersion);
public sealed record Telemetry(Guid BatchId, string Origin, DateTimeOffset SampledAt, Resources Resources, AgentEvent[] Events, Inventory? Inventory, AgentHealth Health);
public sealed record Identity(Guid EndpointId, string AgentToken,string ServerOrigin="");
public sealed record Envelope(Guid EndpointId, Telemetry Payload, string[] JournalNames)
{
    public bool IsExpired(DateTimeOffset now)=>Payload.SampledAt<now-TimeSpan.FromDays(6)||Payload.Events.Any(e=>e.OccurredAt<now-TimeSpan.FromDays(6));
}
public sealed record EnrollmentRequest(string Token,string Hostname,string Ip,string Os,string AgentVersion);
public sealed record EnrollmentResponse([property: JsonPropertyName("endpointId")]Guid EndpointId,[property: JsonPropertyName("agentToken")]string AgentToken,[property: JsonPropertyName("protocolVersion")]int ProtocolVersion=0);

public sealed class AgentOptions
{
    public string ServerUrl { get; set; } = "";
    public string DataDirectory { get; set; } = "";
    public string ServiceName { get; set; } = "SentinelAgent";
    public bool AllowHttpLoopbackDevelopment { get; set; }
    public int IntervalSeconds { get; set; } = 15;
    public int InventoryIntervalSeconds { get; set; } = 300;
    public int MaxQueueFiles { get; set; } = 10000;
    public long MaxQueueBytes { get; set; } = 134217728;
    public string[] FileIntegrityPaths { get; set; } = [];
    public string[] KnownBadHashes { get; set; } = [];
    public bool AnalyzeCommandLinesLocally { get; set; } = true;
    public LogChannel[] EventChannels { get; set; } = [new("Security","*[System[(EventID=4624 or EventID=4625 or EventID=4688)]]"),new("System","*[System[(EventID=7045)]]")];
    public void Validate()
    {
        if(ServerUrl is null||DataDirectory is null||ServiceName is null||EventChannels is null||FileIntegrityPaths is null||KnownBadHashes is null)throw new InvalidDataException("Configuration fields cannot be null.");
        if(!Uri.TryCreate(ServerUrl,UriKind.Absolute,out var uri) || !string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Query) || !string.IsNullOrEmpty(uri.Fragment) || uri.AbsolutePath!="/") throw new InvalidDataException("ServerUrl must be an origin without credentials, path, query or fragment.");
        if(uri.Scheme!="https" && !(AllowHttpLoopbackDevelopment && uri.Scheme=="http" && uri.IsLoopback)) throw new InvalidDataException("HTTPS is required; only an explicit loopback development exception is supported.");
        if(!Path.IsPathFullyQualified(DataDirectory) || DataDirectory.StartsWith("\\\\",StringComparison.Ordinal)) throw new InvalidDataException("DataDirectory must be an absolute local path.");
        if(IntervalSeconds is <5 or >300 || InventoryIntervalSeconds is <30 or >3600) throw new InvalidDataException("Sampling intervals are out of bounds.");
        if(MaxQueueFiles is <10 or >100000 || MaxQueueBytes is <1048576 or >1073741824) throw new InvalidDataException("Buffer limits are out of bounds.");
        if(!System.Text.RegularExpressions.Regex.IsMatch(ServiceName,"^[A-Za-z0-9_-]{3,80}$")) throw new InvalidDataException("Invalid service name.");
        if(EventChannels.Length>8 || FileIntegrityPaths.Length>32 || KnownBadHashes.Length>10000) throw new InvalidDataException("Collection scope is too large.");
        if(KnownBadHashes.Any(h=>!System.Text.RegularExpressions.Regex.IsMatch(h,"^[a-fA-F0-9]{64}$"))) throw new InvalidDataException("Invalid SHA-256 indicator.");
        foreach(var p in FileIntegrityPaths) if(!Path.IsPathFullyQualified(p)||p.StartsWith("\\\\",StringComparison.Ordinal)) throw new InvalidDataException("File integrity paths must be absolute local paths.");
        foreach(var c in EventChannels) if(c is null||c.Name is null||c.Query is null||c.Name.Length is <1 or >120 || c.Query.Length is <1 or >2048) throw new InvalidDataException("Invalid event channel configuration.");
    }
}
public sealed record LogChannel(string Name,string Query);
