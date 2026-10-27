#Requires -RunAsAdministrator
param([Parameter(Mandatory)][ValidateSet('start','stop','status','uninstall')][string]$Action,[string]$ServiceName='SentinelAgent')
. (Join-Path $PSScriptRoot 'Common.ps1')
Assert-Admin
$paths=Get-AgentPaths $ServiceName;Assert-OwnService $paths
switch ($Action) {
    'start' { Start-Service $ServiceName; (Get-Service $ServiceName).WaitForStatus('Running',[TimeSpan]::FromSeconds(30)) }
    'stop' { Stop-Service $ServiceName; (Get-Service $ServiceName).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30)) }
    'status' { Get-Service $ServiceName; & "$env:SystemRoot\System32\sc.exe" qfailure $ServiceName }
    'uninstall' {
        Stop-Service $ServiceName -ErrorAction SilentlyContinue
        (Get-Service $ServiceName).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
        $readers=Get-LocalGroup -SID 'S-1-5-32-573';Remove-LocalGroupMember -Group $readers.Name -Member "NT SERVICE\$ServiceName" -ErrorAction SilentlyContinue
        Invoke-Sc @('delete',$ServiceName)
        Assert-LocalTree $paths.Install
        Remove-Item -LiteralPath $paths.Install -Recurse -Force
        Write-Host "Service and binaries removed. Protected state retained at $($paths.Root). Revoke the endpoint in the dashboard."
    }
}
