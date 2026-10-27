using System.Security.AccessControl;
using System.Security.Principal;
namespace Sentinel.Agent.Windows;
public static class SecureDirectory
{
    private static HashSet<string> Allowed(string service)=>[new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null).Value,new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null).Value,((SecurityIdentifier)new NTAccount("NT SERVICE",service).Translate(typeof(SecurityIdentifier))).Value];
    public static void Validate(string path,string service)
    {
        var info=new DirectoryInfo(path);
        if(!info.Exists||(info.Attributes&FileAttributes.ReparsePoint)!=0)throw new UnauthorizedAccessException("Protected local state directory is missing or is a reparse point.");
        var security=info.GetAccessControl();
        if(!security.AreAccessRulesProtected)throw new UnauthorizedAccessException("State directory must have an explicit protected DACL.");
        var allowed=Allowed(service);
        var owner=security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier ?? throw new UnauthorizedAccessException("Missing trusted owner.");
        if(!allowed.Contains(owner.Value))throw new UnauthorizedAccessException("State directory owner is not trusted.");
        foreach(FileSystemAccessRule rule in security.GetAccessRules(true,true,typeof(SecurityIdentifier)))
            if(rule.AccessControlType==AccessControlType.Allow&&!allowed.Contains(rule.IdentityReference.Value))throw new UnauthorizedAccessException("State directory grants access outside SYSTEM, administrators and this service identity.");
    }
    public static void ValidateConfig(string path,string service)
    {
        var info=new FileInfo(path);if((info.Attributes&FileAttributes.ReparsePoint)!=0)throw new UnauthorizedAccessException("Configuration cannot be a reparse point.");
        var security=info.GetAccessControl();var administrators=new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid,null).Value;var system=new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null).Value;
        var owner=security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier ?? throw new UnauthorizedAccessException("Missing trusted owner.");
        if(owner.Value!=administrators&&owner.Value!=system)throw new UnauthorizedAccessException("Configuration owner must be SYSTEM or administrators.");
        const FileSystemRights writes=FileSystemRights.Write|FileSystemRights.Delete|FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership;
        foreach(FileSystemAccessRule rule in security.GetAccessRules(true,true,typeof(SecurityIdentifier)))
            if(rule.AccessControlType==AccessControlType.Allow&&(rule.FileSystemRights&writes)!=0&&rule.IdentityReference.Value!=administrators&&rule.IdentityReference.Value!=system)throw new UnauthorizedAccessException("Configuration is writable by an untrusted principal.");
    }
}
