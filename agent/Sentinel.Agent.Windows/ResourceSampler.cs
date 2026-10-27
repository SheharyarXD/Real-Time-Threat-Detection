using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using Sentinel.Agent.Core;
namespace Sentinel.Agent.Windows;
public sealed class ResourceSampler
{
    private ulong idle,kernel,user;private long network;private DateTimeOffset sampled;
    public Resources Sample()
    {
        if(!GetSystemTimes(out var i,out var k,out var u))throw new InvalidOperationException("CPU counters unavailable.");
        var memory=new MemoryStatus {Length=(uint)Marshal.SizeOf<MemoryStatus>()};
        if(!GlobalMemoryStatusEx(ref memory))throw new InvalidOperationException("Memory counters unavailable.");
        var now=DateTimeOffset.UtcNow;var total=Networks().Sum(n=>{var s=n.GetIPStatistics();return s.BytesReceived+s.BytesSent;});
        double cpu=0;int rate=0;
        if(sampled!=default)
        {
            var delta=(k.Value-kernel)+(u.Value-user);if(delta>0)cpu=100d*(1d-(double)(i.Value-idle)/delta);
            rate=(int)Math.Clamp((total-network)/Math.Max(.001,(now-sampled).TotalSeconds),0,int.MaxValue);
        }
        (idle,kernel,user,network,sampled)=(i.Value,k.Value,u.Value,total,now);
        var drive=new DriveInfo(Path.GetPathRoot(Environment.SystemDirectory)!);
        var disk=drive.TotalSize>0?100d*(drive.TotalSize-drive.AvailableFreeSpace)/drive.TotalSize:0;
        return new(Math.Clamp(cpu,0,100),memory.TotalPhysical>0?100d*(memory.TotalPhysical-memory.AvailablePhysical)/memory.TotalPhysical:0,Math.Clamp(disk,0,100),rate);
    }
    private static NetworkInterface[] Networks()=>NetworkInterface.GetAllNetworkInterfaces().Where(n=>n.OperationalStatus==OperationalStatus.Up&&n.NetworkInterfaceType is not(NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel)).ToArray();
    public static string Address()=>Networks().SelectMany(n=>n.GetIPProperties().UnicastAddresses).Select(a=>a.Address).FirstOrDefault(a=>a.AddressFamily==AddressFamily.InterNetwork&&!IPAddress.IsLoopback(a))?.ToString()??IPAddress.Loopback.ToString();
    [StructLayout(LayoutKind.Sequential)]private struct NativeTime {public uint Low;public uint High;public readonly ulong Value=>((ulong)High<<32)|Low;}
    [StructLayout(LayoutKind.Sequential)]private struct MemoryStatus {public uint Length;public uint Load;public ulong TotalPhysical;public ulong AvailablePhysical;public ulong TotalPageFile;public ulong AvailablePageFile;public ulong TotalVirtual;public ulong AvailableVirtual;public ulong AvailableExtendedVirtual;}
    [DllImport("kernel32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)][DefaultDllImportSearchPaths(DllImportSearchPath.System32)]private static extern bool GetSystemTimes(out NativeTime idle,out NativeTime kernel,out NativeTime user);
    [DllImport("kernel32.dll",SetLastError=true)][return:MarshalAs(UnmanagedType.Bool)][DefaultDllImportSearchPaths(DllImportSearchPath.System32)]private static extern bool GlobalMemoryStatusEx(ref MemoryStatus status);
}
