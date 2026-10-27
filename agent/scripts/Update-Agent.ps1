#Requires -RunAsAdministrator
param([Parameter(Mandatory)][string]$PackagePath,[string]$ServiceName='SentinelAgent',[string]$PublisherThumbprint='',[switch]$AllowUnsignedDevelopment)
. (Join-Path $PSScriptRoot 'Common.ps1')
Assert-Admin
$paths=Get-AgentPaths $ServiceName;Assert-OwnService $paths
$metadata=Get-Content -LiteralPath (Join-Path $paths.Root 'installation.json') -Raw | ConvertFrom-Json
if ($metadata.publisher -and ($PublisherThumbprint -ne $metadata.publisher -or $AllowUnsignedDevelopment)) { throw 'Publisher changes and signed-to-unsigned downgrades require a separate reviewed installation.' }
$package=Assert-Package $PackagePath $PublisherThumbprint -AllowUnsignedDevelopment:$AllowUnsignedDevelopment
$version=(Get-Content -LiteralPath (Join-Path $package 'manifest.json') -Raw | ConvertFrom-Json).version
if ([Version]$version -lt [Version]$metadata.version) { throw 'Release downgrade rejected.' }
$current=Join-Path $paths.Install 'current';$previous=Join-Path $paths.Install 'previous';$staged=Join-Path $paths.Install 'staged'
Assert-LocalTree $paths.Install
if ((Test-Path $previous) -or (Test-Path $staged)) { throw 'Previous or staged release already exists. Review and archive it before another update.' }
New-Item -ItemType Directory -Path $staged | Out-Null
Copy-Item -Path (Join-Path $package '*') -Destination $staged
Assert-Package $staged $PublisherThumbprint -AllowUnsignedDevelopment:$AllowUnsignedDevelopment | Out-Null
& (Join-Path $staged 'Sentinel.Agent.exe') validate-config --config $paths.Config
if ($LASTEXITCODE -ne 0) { throw 'New binary rejected the existing configuration.' }
Stop-Service $ServiceName;(Get-Service $ServiceName).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
Move-Item -LiteralPath $current -Destination $previous
try {
    Move-Item -LiteralPath $staged -Destination $current
    Start-Service $ServiceName;(Get-Service $ServiceName).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
    $metadata.version=$version;$metadata.publisher=$PublisherThumbprint;$metadata.unsignedDevelopment=[bool]$AllowUnsignedDevelopment
    $metadata | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $paths.Root 'installation.json') -Encoding UTF8
    Write-Host 'Local upgrade started. Verify backend acknowledgment and collector health before archiving previous release.'
} catch {
    Stop-Service $ServiceName -ErrorAction SilentlyContinue
    if (Test-Path $current) { Move-Item -LiteralPath $current -Destination (Join-Path $paths.Install 'failed') }
    Move-Item -LiteralPath $previous -Destination $current
    Start-Service $ServiceName
    throw 'Upgrade failed; previous binary restored. Review Application event logs.'
}
