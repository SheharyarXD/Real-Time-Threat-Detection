using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
namespace Sentinel.Agent.Windows;
public sealed record SignatureResult(string Status,string Publisher);
public sealed class SignatureVerifier
{
    private readonly Dictionary<string,(long Stamp,SignatureResult Result)> cache=new(StringComparer.OrdinalIgnoreCase);
    public SignatureResult Verify(string path)
    {
        if(string.IsNullOrEmpty(path)||!File.Exists(path))return new("unavailable","");
        try
        {
            var stamp=File.GetLastWriteTimeUtc(path).Ticks;
            if(cache.TryGetValue(path,out var entry)&&entry.Stamp==stamp)return entry.Result;
            var info=new WinTrustFileInfo {StructSize=(uint)Marshal.SizeOf<WinTrustFileInfo>(),FilePath=path};
            var ptr=Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
            int result;
            try
            {
                Marshal.StructureToPtr(info,ptr,false);
                var data=new WinTrustData {StructSize=(uint)Marshal.SizeOf<WinTrustData>(),UiChoice=2,RevocationChecks=1,UnionChoice=1,FileInfo=ptr,StateAction=1,ProviderFlags=0x80|0x1000};
                var action=new Guid("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
                try {result=WinVerifyTrust(new IntPtr(-1),ref action,ref data);}
                finally {data.StateAction=2;_ =WinVerifyTrust(new IntPtr(-1),ref action,ref data);}
            }
            finally {Marshal.DestroyStructure<WinTrustFileInfo>(ptr);Marshal.FreeHGlobal(ptr);}
            var status=result==0?"valid_cached_chain":unchecked((uint)result)==0x800B0100?"unsigned_or_catalog_not_checked":"untrusted_or_verification_unavailable";
            string publisher="";
            if(result==0)
            {
                // Authenticode PE extraction has no X509CertificateLoader equivalent.
#pragma warning disable SYSLIB0057
                try {using var certificate=X509Certificate.CreateFromSignedFile(path);publisher=certificate.Subject;}
#pragma warning restore SYSLIB0057
                catch(System.Security.Cryptography.CryptographicException){publisher="catalog_or_no_embedded_publisher";}
            }
            var value=new SignatureResult(status,publisher);
            if(cache.Count>=256)cache.Clear();cache[path]=(stamp,value);return value;
        }
        catch(Exception error) when(error is IOException or UnauthorizedAccessException or System.Security.Cryptography.CryptographicException){return new("unavailable","");}
    }
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] private struct WinTrustFileInfo {public uint StructSize;[MarshalAs(UnmanagedType.LPWStr)]public string FilePath;public IntPtr FileHandle;public IntPtr KnownSubject;}
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] private struct WinTrustData {public uint StructSize;public IntPtr PolicyCallback;public IntPtr SipClient;public uint UiChoice;public uint RevocationChecks;public uint UnionChoice;public IntPtr FileInfo;public uint StateAction;public IntPtr StateData;public IntPtr UrlReference;public uint ProviderFlags;public uint UiContext;public IntPtr SignatureSettings;}
    [DllImport("wintrust.dll",ExactSpelling=true,PreserveSig=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int WinVerifyTrust(IntPtr hwnd,ref Guid action,ref WinTrustData data);
}
