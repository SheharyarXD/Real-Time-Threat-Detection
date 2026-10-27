using System.Security.Cryptography;
using Microsoft.Win32;
using Sentinel.Agent.Core;
namespace Sentinel.Agent.Windows;
public sealed class FileIntegrityCollector(AgentOptions options,ProtectedFiles files,SignatureVerifier signatures)
{
    private Dictionary<string,string> baseline=files.Exists("integrity.bin")?files.Read<Dictionary<string,string>>("integrity.bin"):new(StringComparer.OrdinalIgnoreCase);
    public bool ScopeLimited {get;private set;}
    public sealed record Pending(Dictionary<string,string> Baseline,AgentEvent[] Events,bool Limited);
    public AgentEvent[] Collect()
    {
        if(files.Exists("integrity-pending.bin")){var saved=files.Read<Pending>("integrity-pending.bin");ScopeLimited=saved.Limited;return saved.Events;}
        ScopeLimited=false;
        var current=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);var events=new List<AgentEvent>();
        var configured=options.FileIntegrityPaths.Length>0?options.FileIntegrityPaths:[Path.Combine(Environment.SystemDirectory,"drivers","etc","hosts")];
        foreach(var root in configured)
        {
            if(File.Exists(root))Inspect(root,current,events);
            else if(Directory.Exists(root))
            {
                if((File.GetAttributes(root)&FileAttributes.ReparsePoint)!=0)continue;
                foreach(var file in Scope(root))Inspect(file,current,events);
            }
            else {current[root]="missing";if(baseline.TryGetValue(root,out var before)&&before!="missing")events.Add(Change(root,before,"missing"));}
        }
        foreach(var key in baseline.Keys.Where(k=>!current.ContainsKey(k)&&!k.StartsWith("registry:",StringComparison.Ordinal)&&!k.StartsWith("indicator:",StringComparison.Ordinal)))
            events.Add(Change(key,baseline[key],"missing"));
        foreach(var view in new[]{RegistryView.Registry64,RegistryView.Registry32})
        {
            using var machine=RegistryKey.OpenBaseKey(RegistryHive.LocalMachine,view);
            foreach(var path in new[]{@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"})
            {
                using var key=machine.OpenSubKey(path,false);if(key is null)continue;
                foreach(var name in key.GetValueNames().Take(200))
                {
                    var content=Convert.ToString(key.GetValue(name))??"";var id=$"registry:{view}:{path}:{name}";var hash=Signals.Hash(content);current[id]=hash;
                    if(baseline.TryGetValue(id,out var old)&&old!=hash || baseline.Count>0&&!baseline.ContainsKey(id))
                        events.Add(new(Guid.NewGuid(),"Startup registry entry changed","Registry integrity","persistence",DateTimeOffset.UtcNow,"A monitored startup value changed. Raw registry command text is not transmitted.",null,["persistence_registry_change"],new(){{"registry_key",Wire.Bounded(id,500)},{"image_path",Wire.Bounded(InventoryCollector.ImageOnly(content),500)}}));
                }
            }
        }
        foreach(var id in baseline.Keys.Where(k=>k.StartsWith("registry:",StringComparison.Ordinal)&&!current.ContainsKey(k)))
            events.Add(new(Guid.NewGuid(),"Startup registry entry removed","Registry integrity","persistence",DateTimeOffset.UtcNow,"A monitored startup value was removed; review the authorized change.",null,["persistence_registry_change"],new(){{"registry_key",Wire.Bounded(id,500)}}));
        if(events.Count>1000)throw new InvalidDataException("File integrity scope exceeds 1000 changes; reduce the approved scope.");
        var pending=new Pending(current,events.ToArray(),ScopeLimited);files.Write("integrity-pending.bin",pending);return pending.Events;
    }
    public void Commit()
    {
        var pending=files.Read<Pending>("integrity-pending.bin");files.Write("integrity.bin",pending.Baseline);baseline=pending.Baseline;files.Delete("integrity-pending.bin");
    }
    private static string[] Scope(string root)
    {
        var files=Directory.EnumerateFiles(root,"*",SearchOption.TopDirectoryOnly).Take(1001).ToArray();
        if(files.Length>1000)throw new InvalidDataException("A selected directory exceeds the 1000-file scope; select narrower paths.");
        return files;
    }
    private void Inspect(string path,Dictionary<string,string> current,List<AgentEvent> events)
    {
        try
        {
            var info=new FileInfo(path);if((info.Attributes&FileAttributes.ReparsePoint)!=0||info.Length>16777216){ScopeLimited=true;current[path]="not_hashed_scope_limit";return;}
            using var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete);
            var hash=Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();current[path]=hash;
            if(baseline.TryGetValue(path,out var old)&&old!=hash || baseline.Count>0&&!baseline.ContainsKey(path))events.Add(Change(path,baseline.GetValueOrDefault(path,"new"),hash));
            if(options.KnownBadHashes.Contains(hash,StringComparer.OrdinalIgnoreCase))
            {
                current["indicator:"+path]=hash;
            }
            if(options.KnownBadHashes.Contains(hash,StringComparer.OrdinalIgnoreCase)&&baseline.GetValueOrDefault("indicator:"+path)!=hash)
            {
                var signature=signatures.Verify(path);
                events.Add(new(Guid.NewGuid(),"Configured SHA-256 indicator matched","Local file indicators","malware",DateTimeOffset.UtcNow,"A locally configured hash indicator matched. This is an indicator finding, not proof of active exploitation.",null,["known_hash_indicator"],new(){{"file_path",Wire.Bounded(path,500)},{"image_sha256",hash},{"signature_status",signature.Status},{"rule_hash_source","operator_local_config"}}));
            }
        }
        catch(Exception error)when(error is IOException or UnauthorizedAccessException){throw new IOException("Selected integrity file unavailable; baseline retained.",error);}
    }
    private static AgentEvent Change(string path,string before,string after)=>new(Guid.NewGuid(),"Monitored file changed","File integrity","file",DateTimeOffset.UtcNow,"A selected file changed relative to the locally protected baseline.",null,["sensitive_file_changed"],new(){{"file_path",Wire.Bounded(path,500)},{"prior_sha256",before},{"image_sha256",after}});
}
