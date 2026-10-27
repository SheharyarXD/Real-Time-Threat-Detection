#Requires -RunAsAdministrator
$ErrorActionPreference='Stop'
$server=Read-Host 'Backend HTTPS origin'
& (Join-Path $PSScriptRoot 'Install-Agent.ps1') -ServerUrl $server -AllowUnsignedDevelopment
