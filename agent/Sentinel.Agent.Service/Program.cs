using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Sentinel.Agent.Core;
using Sentinel.Agent.Service;
using Sentinel.Agent.Windows;
using System.Runtime.InteropServices;

if(!OperatingSystem.IsWindows()){Console.Error.WriteLine("This agent requires Windows. Core protocol tests can run on other platforms.");return 1;}
try
{
    string verb=args.Length>0&&!args[0].StartsWith("--",StringComparison.Ordinal)?args[0]:"run";
    string path=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"Sentinel","agent.json");
    for(int i=verb=="run"&&args.Length>0&&args[0].StartsWith("--",StringComparison.Ordinal)?0:1;i<args.Length;i++)
    {if(args[i]=="--config"&&i+1<args.Length)path=Path.GetFullPath(args[++i]);else throw new InvalidDataException("Only --config PATH is accepted; secrets must not be passed as arguments.");}
    if(verb is not("run" or "enroll" or "validate-config"))throw new InvalidDataException("Supported local modes: run, enroll, validate-config.");
    var options=System.Text.Json.JsonSerializer.Deserialize<AgentOptions>(File.ReadAllText(path),Wire.Json)??throw new InvalidDataException("Configuration is empty.");options.Validate();
    if(verb=="validate-config"){Console.WriteLine("Configuration valid. No credentials were read or remote actions enabled.");return 0;}
    SecureDirectory.ValidateConfig(path,options.ServiceName);
    SecureDirectory.Validate(options.DataDirectory,options.ServiceName);
    var files=new ProtectedFiles(options.DataDirectory,new DpapiProtector());
    using var handler=new HttpClientHandler {AllowAutoRedirect=false,CheckCertificateRevocationList=true};
    using var client=new HttpClient(handler){Timeout=TimeSpan.FromSeconds(20),MaxResponseContentBufferSize=65536};
    var transport=new AgentTransport(client,new Uri(options.ServerUrl));
    if(verb=="enroll")
    {
        if(files.Exists("identity.bin"))throw new InvalidDataException("An identity already exists. Re-enrollment requires an explicit operator-controlled reset and fresh protected data directory.");
        // The installer writes the token to redirected stdin, never process arguments.
        var token=(await Console.In.ReadLineAsync())?.Trim()??"";
        if(token.Length is <32 or >128)throw new InvalidDataException("A single-use enrollment token is required on stdin.");
        var identity=await transport.Enroll(new(token,Environment.MachineName,ResourceSampler.Address(),RuntimeInformation.OSDescription,"0.3.0"),CancellationToken.None);
        files.Write("identity.bin",identity);Console.WriteLine("Endpoint enrollment persisted in a DPAPI-protected identity record.");return 0;
    }
    if(!files.Exists("identity.bin"))throw new InvalidDataException("Agent is not enrolled. Use the controlled local enrollment procedure.");
    var builder=Host.CreateApplicationBuilder(new HostApplicationBuilderSettings{Args=[],ContentRootPath=AppContext.BaseDirectory});
    builder.Services.AddWindowsService(o=>o.ServiceName=options.ServiceName);
    builder.Logging.ClearProviders();builder.Logging.AddJsonConsole();builder.Logging.AddEventLog(o=>o.SourceName="Sentinel.Agent");
    builder.Services.AddSingleton(options);builder.Services.AddSingleton(files);builder.Services.AddSingleton(transport);builder.Services.AddHostedService<AgentWorker>();
    await builder.Build().RunAsync();return 0;
}
catch(Exception error)when(error is IOException or InvalidDataException or UnauthorizedAccessException or System.Text.Json.JsonException or HttpRequestException or InvalidOperationException or System.Security.Cryptography.CryptographicException)
{Console.Error.WriteLine($"Agent startup/enrollment failed ({error.GetType().Name}). Check configuration, TLS, permissions and backend state. Secrets and response bodies were not logged.");return 1;}
