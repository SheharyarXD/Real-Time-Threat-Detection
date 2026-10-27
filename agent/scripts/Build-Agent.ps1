[CmdletBinding()]
param([string]$PublisherThumbprint='',[string]$TimestampServer='')
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
if (!(Get-Command dotnet -ErrorAction SilentlyContinue)) { throw 'Install the .NET 10 SDK or run build-agent.bat.' }
if ((& dotnet --version) -notmatch '^10\.') { throw 'A .NET 10 SDK is required.' }
$publish=Join-Path $root 'artifacts\win-x64'
if (Test-Path $publish) { Remove-Item -LiteralPath $publish -Recurse -Force }
& dotnet publish (Join-Path $root 'Sentinel.Agent.Service') -c Release -r win-x64 --self-contained true -m:1 -p:PublishSingleFile=false -o $publish
if ($LASTEXITCODE -ne 0) { throw 'Agent publish failed.' }
if ($PublisherThumbprint) {
    $cert=Get-Item "Cert:\CurrentUser\My\$PublisherThumbprint"
    if (!$cert.HasPrivateKey) { throw 'Signing certificate private key unavailable.' }
    if (!$TimestampServer) { throw 'Provide the approved timestamp server when signing a release.' }
    $result=Set-AuthenticodeSignature -LiteralPath (Join-Path $publish 'Sentinel.Agent.exe') -Certificate $cert -HashAlgorithm SHA256 -TimestampServer $TimestampServer
    if ($result.Status -ne 'Valid') { throw 'Authenticode signing failed.' }
}
$files=@(Get-ChildItem -LiteralPath $publish -File | Sort-Object Name | ForEach-Object { @{path=$_.Name;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()} })
$manifest=@{version='0.3.0';runtime='win-x64';files=$files} | ConvertTo-Json -Depth 5
$manifestPath=Join-Path $publish 'manifest.json'
[IO.File]::WriteAllText($manifestPath,$manifest,(New-Object Text.UTF8Encoding($false)))
if ($PublisherThumbprint) {
    Add-Type -AssemblyName System.Security
    $content=New-Object Security.Cryptography.Pkcs.ContentInfo(,[IO.File]::ReadAllBytes($manifestPath))
    $cms=New-Object Security.Cryptography.Pkcs.SignedCms($content,$true)
    $signer=New-Object Security.Cryptography.Pkcs.CmsSigner($cert)
    $signer.DigestAlgorithm=New-Object Security.Cryptography.Oid('2.16.840.1.101.3.4.2.1')
    $cms.ComputeSignature($signer)
    [IO.File]::WriteAllBytes((Join-Path $publish 'manifest.p7s'),$cms.Encode())
}
Write-Host "Package created: $publish"
