Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Assert-Admin {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this script in an elevated PowerShell window.' }
}
function Get-AgentPaths([string]$Name) {
    if ($Name -notmatch '^[A-Za-z0-9_-]{3,80}$') { throw 'Invalid service name.' }
    $root = Join-Path $env:ProgramData "Sentinel\$Name"
    [pscustomobject]@{ Root=$root; Data=(Join-Path $root 'state'); Config=(Join-Path $root 'agent.json'); Install=(Join-Path $env:ProgramFiles "Sentinel\$Name"); Name=$Name }
}
function Assert-LocalTree([string]$Path) {
    $item = Get-Item -LiteralPath $Path
    while ($null -ne $item) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse points are not supported in installation paths.' }
        $item = $item.Parent
    }
}
function Set-ProtectedDirectory([string]$Path,[string]$Service,[bool]$Writable) {
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
    Assert-LocalTree $Path
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $acl.SetOwner($admins)
    $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'
    foreach ($sid in @($admins,$system)) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl',$inherit,'None','Allow')))
    }
    if ($Service) {
        $identity = New-Object Security.Principal.NTAccount("NT SERVICE\$Service")
        $rights = if ($Writable) { 'Modify' } else { 'ReadAndExecute' }
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity,$rights,$inherit,'None','Allow')))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Assert-Package([string]$Path,[string]$PublisherThumbprint,[switch]$AllowUnsignedDevelopment) {
    $Path = (Resolve-Path -LiteralPath $Path).Path
    Assert-LocalTree $Path
    $manifestPath = Join-Path $Path 'manifest.json'
    $bytes = [IO.File]::ReadAllBytes($manifestPath)
    if (!$AllowUnsignedDevelopment) {
        if ($PublisherThumbprint -notmatch '^[A-Fa-f0-9]{40}$') { throw 'A trusted publisher certificate thumbprint is required.' }
        Add-Type -AssemblyName System.Security
        $content = New-Object Security.Cryptography.Pkcs.ContentInfo(,$bytes)
        $cms = New-Object Security.Cryptography.Pkcs.SignedCms($content,$true)
        $cms.Decode([IO.File]::ReadAllBytes((Join-Path $Path 'manifest.p7s')))
        $cms.CheckSignature($false)
        if ($cms.SignerInfos.Count -ne 1 -or $cms.SignerInfos[0].Certificate.Thumbprint -ne $PublisherThumbprint) { throw 'Manifest publisher does not match the trusted certificate.' }
    } else { Write-Warning 'Explicit development installation of an unsigned package. Do not distribute as a signed release.' }
    $manifest = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
    if ($manifest.version -notmatch '^0\.[0-9]+\.[0-9]+$' -or !$manifest.files) { throw 'Unsupported or empty package manifest.' }
    $seen = @{}
    foreach ($file in $manifest.files) {
        if ($file.path -notmatch '^[A-Za-z0-9_.-]+$' -or $file.sha256 -notmatch '^[a-fA-F0-9]{64}$' -or $seen.ContainsKey($file.path)) { throw 'Invalid or duplicate package entry.' }
        $seen[$file.path]=$true
        $target = Join-Path $Path $file.path
        if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $file.sha256) { throw 'Package integrity check failed.' }
    }
    foreach ($file in Get-ChildItem -LiteralPath $Path -Force) {
        if ($file.PSIsContainer -or ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Package must be a flat directory without links.' }
        if ($file.Name -notin @('manifest.json','manifest.p7s') -and !$seen.ContainsKey($file.Name)) { throw 'Unexpected package file.' }
    }
    if (!$seen.ContainsKey('Sentinel.Agent.exe')) { throw 'Agent executable missing from manifest.' }
    if (!$AllowUnsignedDevelopment) {
        $signature = Get-AuthenticodeSignature -LiteralPath (Join-Path $Path 'Sentinel.Agent.exe')
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -ne $PublisherThumbprint) { throw 'Agent Authenticode signature is invalid or publisher differs.' }
    }
    return $Path
}
function Assert-OwnService($Paths) {
    $service = Get-CimInstance Win32_Service -Filter "Name='$($Paths.Name)'"
    $expected = '"' + (Join-Path $Paths.Install 'current\Sentinel.Agent.exe') + '" run --config "' + $Paths.Config + '"'
    if (!$service -or $service.PathName -ne $expected -or !(Test-Path (Join-Path $Paths.Root 'installation.json'))) { throw 'Service does not match this controlled installation.' }
}
function Invoke-Sc([string[]]$Arguments) {
    & "$env:SystemRoot\System32\sc.exe" @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Windows service configuration failed.' }
}
