using System.Text;
namespace Sentinel.Agent.Core;
public interface IDataProtector { byte[] Protect(byte[] data,string purpose); byte[] Unprotect(byte[] data,string purpose); }
public sealed class ProtectedFiles(string root,IDataProtector protector)
{
    public string Root { get; } = Path.GetFullPath(root);
    private readonly object gate=new();
    private string Full(string name)
    {
        var path=Path.GetFullPath(Path.Combine(Root,name));
        if(!path.StartsWith(Root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Path escaped the state directory.");
        return path;
    }
    public bool Exists(string name)=>File.Exists(Full(name));
    public T Read<T>(string name) => Wire.Decode<T>(protector.Unprotect(File.ReadAllBytes(Full(name)),name));
    public void Write<T>(string name,T value)
    {
        lock(gate)
        {
            var file=Full(name);Directory.CreateDirectory(Path.GetDirectoryName(file)!);
            var temporary=file+".tmp-"+Guid.NewGuid().ToString("N");
            try
            {
                var bytes=protector.Protect(Wire.Encode(value),name);
                using(var stream=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None,4096,FileOptions.WriteThrough)){stream.Write(bytes);stream.Flush(true);}
                File.Move(temporary,file,true);
            }
            finally { if(File.Exists(temporary))File.Delete(temporary); }
        }
    }
    public void Delete(string name){lock(gate){File.Delete(Full(name));}}
    public string[] List(string directory)
    {
        var full=Full(directory);Directory.CreateDirectory(full);
        return Directory.GetFiles(full,"*.bin").Select(p=>Path.GetRelativePath(Root,p)).Order(StringComparer.Ordinal).ToArray();
    }
    public long Size(string name)=>new FileInfo(Full(name)).Length;
}
public sealed class DurableBuffer(ProtectedFiles files,string folder,int maxFiles,long maxBytes)
{
    private readonly object gate=new();
    public int Count {get{lock(gate)return files.List(folder).Length;}}
    public bool TryAdd<T>(string id,T value)
    {
        lock(gate)
        {
            var name=Path.Combine(folder,id+".bin");
            if(files.Exists(name)){if(!Wire.Encode(files.Read<T>(name)).AsSpan().SequenceEqual(Wire.Encode(value)))throw new InvalidDataException("A buffered ID was reused with different content.");return true;}
            var existing=files.List(folder);
            // Reserve protection overhead and reject before writing; never overwrite old records silently.
            if(existing.Length>=maxFiles || existing.Sum(files.Size)+Wire.Encode(value).Length+4096>maxBytes)return false;
            files.Write(name,value);return true;
        }
    }
    public (string Name,T Value)[] Read<T>(int count){lock(gate)return files.List(folder).Take(count).Select(n=>(n,files.Read<T>(n))).ToArray();}
    public void Remove(string name){lock(gate)files.Delete(name);}
}
