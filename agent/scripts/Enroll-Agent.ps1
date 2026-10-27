#Requires -RunAsAdministrator
param([string]$ServiceName='SentinelAgent')
. (Join-Path $PSScriptRoot 'Common.ps1')
Assert-Admin
$paths=Get-AgentPaths $ServiceName;Assert-OwnService $paths
if ((Get-Service $ServiceName).Status -ne 'Stopped') { throw 'Stop the service before enrolling.' }
$token=Read-Host 'Single-use enrollment token' -AsSecureString
$ptr=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($token)
try {
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=Join-Path $paths.Install 'current\Sentinel.Agent.exe';$info.Arguments='enroll --config "'+$paths.Config+'"';$info.UseShellExecute=$false;$info.RedirectStandardInput=$true
    $process=[Diagnostics.Process]::Start($info);$process.StandardInput.WriteLine([Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr));$process.StandardInput.Close();$process.WaitForExit()
    if ($process.ExitCode -ne 0) { throw 'Enrollment failed; existing credentials are never overwritten.' }
} finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
