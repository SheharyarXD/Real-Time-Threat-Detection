using System.Management;
using Microsoft.Win32;
using Sentinel.Agent.Core;
namespace Sentinel.Agent.Windows;
public sealed class InventoryCollector(AgentOptions options,SignatureVerifier signatures)
{
    public const int Limit=200;
    public (Inventory Inventory,AgentEvent[] Events) Collect()
    {
        var processes=new List<ProcessEntry>();var services=new List<ServiceEntry>();var software=new List<SoftwareEntry>();var events=new List<AgentEvent>();bool truncated=false;
        using(var search=new ManagementObjectSearcher("SELECT ProcessId,ParentProcessId,Name,ExecutablePath"+(options.AnalyzeCommandLinesLocally?",CommandLine":"")+" FROM Win32_Process"))
        using(var rows=search.Get())
        {
            var entries=new List<(int Pid,int Parent,string Name,string Image,string Command)>();
            foreach(ManagementObject p in rows)using(p)entries.Add((Convert.ToInt32(p["ProcessId"]),Convert.ToInt32(p["ParentProcessId"]),Convert.ToString(p["Name"])??"",Convert.ToString(p["ExecutablePath"])??"",options.AnalyzeCommandLinesLocally?Convert.ToString(p["CommandLine"])??"":""));
            var raw=entries.ToArray();
            var parents=raw.ToDictionary(p=>p.Pid,p=>p.Name);
            foreach(var p in raw.Take(Limit))
            {
                var parent=parents.GetValueOrDefault(p.Parent,"");var signature=processes.Count<20?signatures.Verify(p.Image):new SignatureResult("not_sampled","");
                processes.Add(new(p.Pid,Wire.Bounded(p.Name,200),Wire.Bounded(p.Image,500),Wire.Bounded(parent,200),signature.Status));
                var signals=Signals.Process(p.Name,parent,p.Image,p.Command,signature.Status);
                if(Signals.Actionable(signals))events.Add(new(Guid.NewGuid(),"Correlated suspicious process context","Process inventory","process",DateTimeOffset.UtcNow,"Reported process signals require investigation; a signature state alone is not a malware verdict.",null,signals,new(){{"process_name",Wire.Bounded(p.Name)},{"parent_name",Wire.Bounded(parent)},{"image_path",Wire.Bounded(p.Image,500)},{"signature_status",signature.Status},{"publisher",Wire.Bounded(signature.Publisher)}}));
            }
            truncated|=raw.Length>Limit;
        }
        using(var search=new ManagementObjectSearcher("SELECT Name,State,StartMode,PathName FROM Win32_Service"))
        using(var rows=search.Get())
        {
            foreach(ManagementObject row in rows)
            {
                using(row)
                {
                    if(services.Count>=Limit){truncated=true;break;}
                    services.Add(new(Wire.Bounded(Convert.ToString(row["Name"]),200),Wire.Bounded(Convert.ToString(row["State"]),40),Wire.Bounded(Convert.ToString(row["StartMode"]),40),Wire.Bounded(ImageOnly(Convert.ToString(row["PathName"])??""),500)));
                }
            }
        }
        foreach(var view in new[]{RegistryView.Registry64,RegistryView.Registry32})
        {
            using var machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,view);
            using var uninstall=machine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",false);
            if(uninstall is null)continue;
            foreach(var name in uninstall.GetSubKeyNames())
            {
                using var key=uninstall.OpenSubKey(name,false);var display=key?.GetValue("DisplayName") as string;
                if(string.IsNullOrWhiteSpace(display))continue;
                if(software.Count>=Limit){truncated=true;break;}
                software.Add(new(Wire.Bounded(display,200),Wire.Bounded(key?.GetValue("DisplayVersion") as string,100),Wire.Bounded(key?.GetValue("Publisher") as string,200)));
            }
        }
        return (new(processes.ToArray(),services.ToArray(),software.Distinct().ToArray(),truncated),events.Take(30).ToArray());
    }
    public static string ImageOnly(string command)
    {
        command=Environment.ExpandEnvironmentVariables(command.Trim());
        if(command.StartsWith('"')){var end=command.IndexOf('"',1);return end>1?command[1..end]:"";}
        var exe=command.IndexOf(".exe",StringComparison.OrdinalIgnoreCase);return exe>=0?command[..(exe+4)]:command.Split(' ',2)[0];
    }
}
