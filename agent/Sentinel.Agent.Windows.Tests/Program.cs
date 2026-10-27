using Sentinel.Agent.Core;
using Sentinel.Agent.Windows;
if(!OperatingSystem.IsWindows()){Console.Error.WriteLine("Native Windows tests require Windows.");return 1;}
var root=Path.Combine(Path.GetTempPath(),"sentinel-native-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
int passed=0;
void Check(bool condition,string name){if(!condition)throw new Exception(name);Console.WriteLine("PASS "+name);passed++;}
try
{
    var files=new ProtectedFiles(root,new DpapiProtector());files.Write("identity.bin",new Identity(Guid.NewGuid(),"TEST-ONLY-NATIVE-IDENTITY-"+Guid.NewGuid()));
    Check(!System.Text.Encoding.UTF8.GetString(File.ReadAllBytes(Path.Combine(root,"identity.bin"))).Contains("TEST-ONLY"),"DPAPI encrypts native identity records");
    Check(new ProtectedFiles(root,new DpapiProtector()).Read<Identity>("identity.bin").EndpointId!=Guid.Empty,"DPAPI record survives reopening");
    var sampler=new ResourceSampler();_ =sampler.Sample();await Task.Delay(200);var resource=sampler.Sample();
    Check(resource.Cpu is >=0 and <=100&&resource.Ram is >0 and <=100&&resource.Disk is >=0 and <=100&&resource.NetworkBps>=0,"Native resource counters return bounded observations");
    var signature=new SignatureVerifier();var result=signature.Verify(Path.Combine(Environment.SystemDirectory,"kernel32.dll"));
    Check(result.Status is "valid_cached_chain" or "unsigned_or_catalog_not_checked" or "untrusted_or_verification_unavailable","WinVerifyTrust returns a qualified native trust observation");
    var options=new AgentOptions{ServerUrl="https://soc.example.invalid",DataDirectory=root};
    var inventory=new InventoryCollector(options,signature).Collect().Inventory;
    Check(inventory.Processes.Length>0&&inventory.Services.Length>0&&inventory.Processes.Length<=200&&inventory.Services.Length<=200&&inventory.Software.Length<=200,"Native WMI and registry inventories respect bounds");
    var target=Path.Combine(root,"selected.txt");File.WriteAllText(target,"before");options.FileIntegrityPaths=[target];
    var fim=new FileIntegrityCollector(options,files,signature);Check(fim.Collect().All(e=>!e.Signals!.Contains("sensitive_file_changed")),"First selected-file sample establishes a baseline");fim.Commit();
    File.WriteAllText(target,"after");var changes=fim.Collect();Check(changes.Any(e=>e.Signals!.Contains("sensitive_file_changed")),"Selected file change generates real integrity evidence");
    Check(new FileIntegrityCollector(options,files,signature).Collect().Select(e=>e.EventUid).SequenceEqual(changes.Select(e=>e.EventUid)),"Pending change set survives restart without changing event identity");fim.Commit();
    File.Delete(target);Check(fim.Collect().Any(e=>e.Signals!.Contains("sensitive_file_changed")),"Selected file deletion generates an integrity observation");fim.Commit();
    var xml="<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><EventData><Data Name='NewProcessName'>C:\\Windows\\powershell.exe</Data><Data Name='ParentProcessName'>C:\\Office\\WINWORD.EXE</Data><Data Name='CommandLine'>-enc QUJDREVGR0g= SECRET-NOT-TRANSMITTED</Data><Data Name='SubjectUserName'>PRIVATE-ACCOUNT</Data></EventData></Event>";
    var parsed=EventCollector.Parse(xml,"Lab","Security",4688,42,DateTimeOffset.UtcNow);var wire=System.Text.Encoding.UTF8.GetString(Wire.Encode(parsed));
    Check(Signals.Actionable(parsed.Signals!)&&!wire.Contains("SECRET-NOT-TRANSMITTED")&&!wire.Contains("PRIVATE-ACCOUNT"),"Event XML derives signals while excluding raw command and account data");
    Console.WriteLine($"{passed} native Windows checks passed.");return 0;
}
finally {Directory.Delete(root,true);}
