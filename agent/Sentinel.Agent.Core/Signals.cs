using System.Text.RegularExpressions;
namespace Sentinel.Agent.Core;
public static class Signals
{
    public static string[] Process(string name,string parent,string image,string command,string signature)
    {
        var signals=new List<string>();
        bool powershell=name.Equals("powershell.exe",StringComparison.OrdinalIgnoreCase)||name.Equals("pwsh.exe",StringComparison.OrdinalIgnoreCase)||name.Equals("powershell",StringComparison.OrdinalIgnoreCase);
        if(powershell && Regex.IsMatch(command,@"(?i)(?:^|\s)-(?:enc|encodedcommand|e)\s+[A-Za-z0-9+/=]{8,}"))signals.Add("encoded_powershell");
        if(powershell && new[]{"w3wp.exe","winword.exe","excel.exe","outlook.exe","mshta.exe"}.Contains(parent,StringComparer.OrdinalIgnoreCase))signals.Add("unusual_parent");
        if(image.Contains("\\temp\\",StringComparison.OrdinalIgnoreCase)||image.Contains("/tmp/",StringComparison.Ordinal))signals.Add("temp_execution");
        if(signature=="unsigned_or_catalog_not_checked")signals.Add("unsigned_image");
        return signals.ToArray();
    }
    public static bool Actionable(IEnumerable<string> signals)
    {
        var s=signals.ToHashSet(StringComparer.Ordinal);
        return s.Contains("known_hash_indicator") || s.Contains("sensitive_file_changed") || s.Contains("persistence_registry_change") || s.Contains("encoded_powershell") && s.Contains("unusual_parent") || s.Contains("temp_execution") && s.Contains("unsigned_image");
    }
    public static string Hash(string value)=>Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
}
