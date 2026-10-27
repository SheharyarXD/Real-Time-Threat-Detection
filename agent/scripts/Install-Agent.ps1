#Requires -RunAsAdministrator
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ServerUrl,[string]$ServiceName='SentinelAgent',[string]$PackagePath=(Join-Path $PSScriptRoot '..\artifacts\win-x64'),[Security.SecureString]$EnrollmentToken,[string]$PublisherThumbprint='',[switch]$AllowUnsignedDevelopment,[switch]$AllowHttpLoopbackDevelopment,[string[]]$FileIntegrityPaths=@())
. (Join-Path $PSScriptRoot 'Common.ps1')
Assert-Admin
$paths=Get-AgentPaths $ServiceName
$package=Assert-Package $PackagePath $PublisherThumbprint -AllowUnsignedDevelopment:$AllowUnsignedDevelopment
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { throw 'Service already exists. Use the controlled upgrade procedure.' }
if ((Test-Path $paths.Root) -or (Test-Path $paths.Install)) { throw 'An installation or retained state already exists. Review it before any reset.' }
# Validate non-secret config before creating any service.
$config=@{server_url=$ServerUrl;data_directory=$paths.Data;service_name=$ServiceName;allow_http_loopback_development=[bool]$AllowHttpLoopbackDevelopment;interval_seconds=15;inventory_interval_seconds=300;max_queue_files=10000;max_queue_bytes=134217728;file_integrity_paths=@($FileIntegrityPaths);known_bad_hashes=@();analyze_command_lines_locally=$true}
$uri=[Uri]$ServerUrl
if (!$uri.IsAbsoluteUri -or $uri.AbsolutePath -ne '/' -or $uri.UserInfo -or $uri.Query -or $uri.Fragment -or ($uri.Scheme -ne 'https' -and !($AllowHttpLoopbackDevelopment -and $uri.Scheme -eq 'http' -and $uri.IsLoopback))) { throw 'Use an HTTPS origin, or the explicit loopback development exception.' }
Set-ProtectedDirectory $paths.Root '' $false
Set-ProtectedDirectory $paths.Install '' $false
$current=Join-Path $paths.Install 'current';New-Item -ItemType Directory -Path $current | Out-Null
Copy-Item -Path (Join-Path $package '*') -Destination $current
Assert-Package $current $PublisherThumbprint -AllowUnsignedDevelopment:$AllowUnsignedDevelopment | Out-Null
$binary=Join-Path $current 'Sentinel.Agent.exe'
$command='"'+$binary+'" run --config "'+$paths.Config+'"'
New-Service -Name $ServiceName -BinaryPathName $command -DisplayName "Sentinel Monitoring ($ServiceName)" -StartupType Automatic | Out-Null
Invoke-Sc @('config',$ServiceName,'obj=',"NT SERVICE\$ServiceName")
Invoke-Sc @('sidtype',$ServiceName,'unrestricted')
Invoke-Sc @('failure',$ServiceName,'reset=','86400','actions=','restart/10000/restart/30000/restart/60000')
Invoke-Sc @('failureflag',$ServiceName,'1')
Invoke-Sc @('config',$ServiceName,'start=','delayed-auto')
Set-ProtectedDirectory $paths.Root $ServiceName $false
Set-ProtectedDirectory $paths.Install $ServiceName $false
Set-ProtectedDirectory $paths.Data $ServiceName $true
$config | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $paths.Config -Encoding UTF8
@{service=$ServiceName;version='0.3.0';publisher=$PublisherThumbprint;unsignedDevelopment=[bool]$AllowUnsignedDevelopment} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $paths.Root 'installation.json') -Encoding UTF8
foreach ($file in @($paths.Config,(Join-Path $paths.Root 'installation.json'))) {
    $acl=Get-Acl -LiteralPath $file;$acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')));Set-Acl -LiteralPath $file -AclObject $acl
}
# Use the well-known SID to support localized Windows installations.
$readers=Get-LocalGroup -SID 'S-1-5-32-573'
Add-LocalGroupMember -Group $readers.Name -Member "NT SERVICE\$ServiceName"
if (![Diagnostics.EventLog]::SourceExists('Sentinel.Agent')) { New-EventLog -LogName Application -Source 'Sentinel.Agent' }
& $binary validate-config --config $paths.Config
if ($LASTEXITCODE -ne 0) { throw 'Configuration validation failed. Service remains stopped.' }
if (!$EnrollmentToken) { $EnrollmentToken=Read-Host 'Paste the single-use enrollment token' -AsSecureString }
$pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($EnrollmentToken)
try {
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$binary;$info.Arguments='enroll --config "'+$paths.Config+'"';$info.UseShellExecute=$false;$info.RedirectStandardInput=$true
    $process=[Diagnostics.Process]::Start($info)
    $process.StandardInput.WriteLine([Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer));$process.StandardInput.Close()
    $process.WaitForExit()
    if ($process.ExitCode -ne 0) { throw 'Enrollment failed. Service remains stopped; inspect configuration and use Enroll-Agent.ps1 to retry with a new token if necessary.' }
} finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
Start-Service $ServiceName
(Get-Service $ServiceName).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
Write-Host 'Agent service is running. Check collector health and provenance in /live.'
