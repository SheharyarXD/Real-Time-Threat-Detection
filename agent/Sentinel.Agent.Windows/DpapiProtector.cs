using System.Security.Cryptography;
using System.Text;
using Sentinel.Agent.Core;
namespace Sentinel.Agent.Windows;
public sealed class DpapiProtector : IDataProtector
{
    public byte[] Protect(byte[] data,string purpose)=>ProtectedData.Protect(data,Encoding.UTF8.GetBytes("Sentinel.Agent.v1:"+purpose),DataProtectionScope.LocalMachine);
    public byte[] Unprotect(byte[] data,string purpose)=>ProtectedData.Unprotect(data,Encoding.UTF8.GetBytes("Sentinel.Agent.v1:"+purpose),DataProtectionScope.LocalMachine);
}
