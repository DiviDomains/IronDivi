<#
.SYNOPSIS
    Generates and installs a self-signed certificate for local testing of MSIX packages.

.DESCRIPTION
    Windows requires MSIX packages installed via Add-AppxPackage (sideloading) to be signed
    by a certificate trusted on the local machine. This script creates a certificate matching
    the publisher identity in AppxManifest.xml, exports a PFX, and installs it into
    Cert:\CurrentUser\Root (Trusted Root Certification Authorities).
#>

[CmdletBinding()]
param (
    [string]$Publisher = "CN=DiviDomains",
    [string]$OutputFile = "irondivi-dev.pfx",
    [string]$Password = "irondivi"
)

$ErrorActionPreference = "Stop"

Write-Host "Creating self-signed certificate for publisher '$Publisher'..." -ForegroundColor Cyan

$Cert = New-SelfSignedCertificate `
    -Type Custom `
    -Subject $Publisher `
    -KeyUsage DigitalSignature `
    -FriendlyName "IronDivi Development Test Cert" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")

$SecPassword = ConvertTo-SecureString -String $Password -Force -AsPlainText
Export-PfxCertificate -Cert $Cert -FilePath $OutputFile -Password $SecPassword | Out-Null
Write-Host "Exported certificate to: $OutputFile" -ForegroundColor Green

# Install into Trusted Root for Current User
$RootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "CurrentUser")
$RootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
$RootStore.Add($Cert)
$RootStore.Close()

Write-Host "Installed into Trusted Root Certification Authorities for Current User." -ForegroundColor Green
Write-Host "You can now install self-signed MSIX packages with: Add-AppxPackage -Path <package.msix>"
