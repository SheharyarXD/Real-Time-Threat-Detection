using System.Net;
using System.Text.Json;
using System.Net.Http.Headers;
namespace Sentinel.Agent.Core;
public sealed class AgentHttpException(int status):InvalidOperationException("Agent server rejected the request."){public int Status {get;}=status;}
public sealed record Delivery(bool Accepted,bool AuthorizationBlocked,bool Permanent,int RetrySeconds);
public sealed class AgentTransport(HttpClient client,Uri origin)
{
    public async Task<Identity> Enroll(EnrollmentRequest payload,CancellationToken cancellation)
    {
        using var request=new HttpRequestMessage(HttpMethod.Post,new Uri(origin,"/api/v1/agent/enroll")){Content=new ByteArrayContent(Wire.Encode(payload))};
        request.Content.Headers.ContentType=new MediaTypeHeaderValue("application/json");
        using var response=await client.SendAsync(request,cancellation);
        if(response.StatusCode!=HttpStatusCode.Created)throw new AgentHttpException((int)response.StatusCode);
        var body=Wire.Decode<EnrollmentResponse>(await response.Content.ReadAsByteArrayAsync(cancellation));
        if(body.ProtocolVersion!=3||body.EndpointId==Guid.Empty || body.AgentToken.Length is <32 or >128)throw new InvalidDataException("Invalid enrollment response.");
        return new Identity(body.EndpointId,body.AgentToken,origin.GetLeftPart(UriPartial.Authority));
    }
    public async Task<Delivery> Send(Identity identity,Envelope envelope,CancellationToken cancellation)
    {
        if(identity.EndpointId!=envelope.EndpointId||identity.ServerOrigin!=origin.GetLeftPart(UriPartial.Authority))throw new InvalidDataException("Buffered telemetry belongs to another endpoint identity.");
        using var request=new HttpRequestMessage(HttpMethod.Post,new Uri(origin,"/api/v1/agent/telemetry")){Content=new ByteArrayContent(Wire.Encode(envelope.Payload))};
        request.Headers.Authorization=new AuthenticationHeaderValue("Bearer",identity.AgentToken);
        request.Content.Headers.ContentType=new MediaTypeHeaderValue("application/json");
        using var response=await client.SendAsync(request,cancellation);
        if(response.StatusCode==HttpStatusCode.Accepted)
        {
            using var acknowledgment=JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(cancellation));
            var root=acknowledgment.RootElement;
            if(root.ValueKind!=JsonValueKind.Object||!root.TryGetProperty("accepted",out var accepted)||accepted.ValueKind!=JsonValueKind.True||!root.TryGetProperty("batchId",out var batch)||batch.ValueKind!=JsonValueKind.String||batch.GetString()!=envelope.Payload.BatchId.ToString())throw new InvalidDataException("Server acknowledgment was not bound to the submitted batch.");
            return new(true,false,false,0);
        }
        int retry=0;
        if(response.Headers.RetryAfter?.Delta is {} delta)retry=(int)Math.Ceiling(delta.TotalSeconds);
        else if(response.Headers.RetryAfter?.Date is {} date)retry=(int)Math.Ceiling((date-DateTimeOffset.UtcNow).TotalSeconds);
        return new(false,response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden,response.StatusCode is HttpStatusCode.BadRequest or HttpStatusCode.RequestEntityTooLarge or HttpStatusCode.UnprocessableEntity or HttpStatusCode.Conflict,Math.Clamp(retry,0,300));
    }
    public static TimeSpan Backoff(int failures,int serverSeconds=0,double jitter=1)=>TimeSpan.FromSeconds(Math.Clamp(Math.Max(Math.Clamp(serverSeconds,0,300),Math.Min(300,Math.Pow(2,Math.Clamp(failures,0,9)))*Math.Clamp(jitter,.8,1.2)),1,300));
}
