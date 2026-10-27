# Run only on an isolated disposable Windows runner with administrator rights.
#Requires -RunAsAdministrator
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot '..\scripts\Common.ps1')
Assert-Admin
$repo=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$env:SENTINEL_CI_LAB=Join-Path $env:RUNNER_TEMP ('sentinel-ci-'+[Guid]::NewGuid().ToString('N'))
Set-ProtectedDirectory $env:SENTINEL_CI_LAB '' $false
$service='SentinelCI'+(Get-Random -Minimum 10000 -Maximum 99999)
$paths=Get-AgentPaths $service
$server=$null
function Start-Lab {
    Start-Process -FilePath (Get-Command python).Source -ArgumentList @((Join-Path $PSScriptRoot 'lab_server.py')) -PassThru -RedirectStandardOutput (Join-Path $env:SENTINEL_CI_LAB 'backend.out') -RedirectStandardError (Join-Path $env:SENTINEL_CI_LAB 'backend.err')
}
try {
    $server=Start-Lab
    $tokenFile=Join-Path $env:SENTINEL_CI_LAB 'enrollment-token.txt'
    for ($i=0;$i -lt 60 -and !(Test-Path $tokenFile);$i++) { Start-Sleep -Seconds 1 }
    if (!(Test-Path $tokenFile)) { throw 'CI backend did not start.' }
    $secure=ConvertTo-SecureString (Get-Content -LiteralPath $tokenFile -Raw) -AsPlainText -Force
    & (Join-Path $PSScriptRoot '..\scripts\Install-Agent.ps1') -ServerUrl 'http://127.0.0.1:18443' -ServiceName $service -EnrollmentToken $secure -AllowUnsignedDevelopment -AllowHttpLoopbackDevelopment
    Stop-Service $service;(Get-Service $service).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
    # Service can traverse this read-only CI folder to hash one approved fixture.
    Set-ProtectedDirectory $env:SENTINEL_CI_LAB $service $false
    $selected=Join-Path $env:SENTINEL_CI_LAB 'selected.txt';'before' | Set-Content $selected
    $config=Get-Content -LiteralPath $paths.Config -Raw | ConvertFrom-Json
    $config.interval_seconds=5;$config.inventory_interval_seconds=30;$config.file_integrity_paths=@($selected)
    $config | Add-Member -NotePropertyName event_channels -NotePropertyValue @(@{name='Application';query='*[System[(EventID=4242)]]'}) -Force
    $config | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $paths.Config -Encoding UTF8
    Start-Service $service
    & python (Join-Path $PSScriptRoot 'assert_lab.py') inventory
    if ($LASTEXITCODE -ne 0) { throw 'Native telemetry failed.' }
    [Diagnostics.EventLog]::WriteEntry('Sentinel.Agent','Explicit isolated CI event fixture',[Diagnostics.EventLogEntryType]::Information,4242)
    'after' | Set-Content -LiteralPath $selected
    & python (Join-Path $PSScriptRoot 'assert_lab.py') events
    if ($LASTEXITCODE -ne 0) { throw 'Native event delivery failed.' }
    $before=& python -c "import sqlite3,os;from pathlib import Path;print(sqlite3.connect(Path(os.environ['SENTINEL_CI_LAB'])/'windows-ci.sqlite').execute('select count(*) from telemetry_batches').fetchone()[0])"
    Stop-Process -Id $server.Id -Force;$server=$null
    Start-Sleep -Seconds 18
    Stop-Service $service;(Get-Service $service).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
    if (@(Get-ChildItem (Join-Path $paths.Data 'outbox') -Filter '*.bin').Count -lt 1) { throw 'Expected protected offline batches.' }
    Start-Service $service
    $server=Start-Lab
    & python (Join-Path $PSScriptRoot 'assert_lab.py') drained $before
    if ($LASTEXITCODE -ne 0) { throw 'Offline restart replay failed.' }
    & (Join-Path $PSScriptRoot '..\scripts\Manage-Agent.ps1') -ServiceName $service -Action status
    & (Join-Path $PSScriptRoot '..\scripts\Manage-Agent.ps1') -ServiceName $service -Action uninstall
    if (Get-Service $service -ErrorAction SilentlyContinue) { throw 'Service uninstall failed.' }
    Write-Host 'PASS native installation, enrollment, service lifecycle, DPAPI, telemetry, EventLog, FIM and offline restart replay.'
} finally {
    if ($server -and !$server.HasExited) { Stop-Process -Id $server.Id -Force }
    if (Get-Service $service -ErrorAction SilentlyContinue) { & (Join-Path $PSScriptRoot '..\scripts\Manage-Agent.ps1') -ServiceName $service -Action uninstall }
    # Isolated runner owns these paths. No state or tokens are uploaded as artifacts.
    if (Test-Path $paths.Root) { Remove-Item -LiteralPath $paths.Root -Recurse -Force }
    if (Test-Path $env:SENTINEL_CI_LAB) { Remove-Item -LiteralPath $env:SENTINEL_CI_LAB -Recurse -Force }
}
