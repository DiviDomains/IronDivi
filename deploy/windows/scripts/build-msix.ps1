<#
.SYNOPSIS
    Packages IronDivi for Microsoft Store and Windows Desktop distribution (MSIX).

.DESCRIPTION
    Assembles irondivid.exe, irondivi-cli.exe, AppxManifest.xml, and visual assets,
    then compiles them into an MSIX package using MakeAppx.exe from the Windows SDK.
    Optionally signs the package with SignTool.exe for local testing.

.PARAMETER BinDir
    Directory containing built binaries (irondivid.exe, irondivi-cli.exe).
    Defaults to target\x86_64-pc-windows-msvc\release or target\release.

.PARAMETER OutputDir
    Output directory for the generated .msix package. Defaults to target\msix.

.PARAMETER Publisher
    The Publisher ID (e.g. 'CN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' from Microsoft Partner Center).
    If omitted, keeps the Publisher from AppxManifest.xml.

.PARAMETER Version
    The package version in Quad format (e.g. '0.2.9.0'). If omitted, extracts from Cargo.toml.

.PARAMETER Sign
    Signs the resulting MSIX package for local testing.

.PARAMETER CertificatePath
    Path to a .pfx code signing certificate. If omitted and -Sign is passed, searches or creates a dev cert.

.PARAMETER CertificatePassword
    Password for the .pfx certificate.

.EXAMPLE
    .\build-msix.ps1 -Sign
    .\build-msix.ps1 -Publisher "CN=YourPartnerCenterID" -Sign
#>

[CmdletBinding()]
param (
    [string]$BinDir = "",
    [string]$OutputDir = "",
    [string]$Publisher = "",
    [string]$Version = "",
    [switch]$Sign,
    [string]$CertificatePath = "",
    [string]$CertificatePassword = ""
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$WindowsDir = Split-Path -Parent $ScriptDir
$DeployDir = Split-Path -Parent $WindowsDir
$RootDir = Split-Path -Parent $DeployDir

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   IronDivi Windows App Store (MSIX) Packager            " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Resolve root and version
if (-not $Version) {
    $CargoPath = Join-Path $RootDir "Cargo.toml"
    if (Test-Path $CargoPath) {
        $CargoContent = Get-Content $CargoPath -Raw
        if ($CargoContent -match 'version\s*=\s*"([^"]+)"') {
            $BaseVersion = $matches[1]
            $Parts = $BaseVersion.Split('.')
            while ($Parts.Length -lt 4) { $Parts += "0" }
            $Version = ($Parts[0..3] -join '.')
            Write-Host "[+] Extracted version from Cargo.toml: $Version (quad: $Version)" -ForegroundColor Green
        }
    }
    if (-not $Version) {
        $Version = "0.2.9.0"
        Write-Host "[!] Defaulting to version: $Version" -ForegroundColor Yellow
    }
}

# 2. Locate binaries
if (-not $BinDir) {
    $Candidates = @(
        (Join-Path $RootDir "target\x86_64-pc-windows-msvc\release"),
        (Join-Path $RootDir "target\release"),
        (Join-Path $RootDir "bin")
    )
    foreach ($c in $Candidates) {
        if ((Test-Path (Join-Path $c "irondivid.exe")) -and (Test-Path (Join-Path $c "irondivi-cli.exe"))) {
            $BinDir = $c
            break
        }
    }
    if (-not $BinDir) {
        $BinDir = $Candidates[0]
    }
}

$DaemonExe = Join-Path $BinDir "irondivid.exe"
$CliExe = Join-Path $BinDir "irondivi-cli.exe"

Write-Host "[*] Looking for binaries in: $BinDir"
if (-not (Test-Path $DaemonExe)) {
    Write-Warning "irondivid.exe not found at '$DaemonExe'."
    Write-Warning "Please compile with: cargo build --release --bin irondivid --bin irondivi-cli"
}
if (-not (Test-Path $CliExe)) {
    Write-Warning "irondivi-cli.exe not found at '$CliExe'."
}

# 3. Locate MakeAppx and SignTool in Windows Kits
function Find-WindowsTool([string]$ToolName) {
    # Check PATH first
    $Found = Get-Command $ToolName -ErrorAction SilentlyContinue
    if ($Found) { return $Found.Source }

    $KitsRoot = "C:\Program Files (x86)\Windows Kits\10\bin"
    if (Test-Path $KitsRoot) {
        $Versions = Get-ChildItem -Directory $KitsRoot | Sort-Object Name -Descending
        foreach ($v in $Versions) {
            $Path = Join-Path $v.FullName "x64\$ToolName"
            if (Test-Path $Path) { return $Path }
        }
    }
    return $null
}

$MakeAppx = Find-WindowsTool "MakeAppx.exe"
$SignTool = Find-WindowsTool "SignTool.exe"

if (-not $MakeAppx) {
    throw "MakeAppx.exe not found. Please install the Windows 10/11 SDK or run from Developer Command Prompt."
}
Write-Host "[+] Found MakeAppx: $MakeAppx" -ForegroundColor Green

# 4. Setup output and staging directory
if (-not $OutputDir) {
    $OutputDir = Join-Path $RootDir "target\msix"
}
$StagingDir = Join-Path $OutputDir "staging"
if (Test-Path $StagingDir) {
    Remove-Item $StagingDir -Recurse -Force
}
New-Item -ItemType Directory -Path $StagingDir -Force | Out-Null
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$MsixSourceDir = Join-Path $WindowsDir "msix"

# 5. Copy Assets
$AssetsSource = Join-Path $MsixSourceDir "Assets"
$AssetsDest = Join-Path $StagingDir "Assets"
Copy-Item $AssetsSource -Destination $AssetsDest -Recurse -Force
Write-Host "[+] Copied visual assets to staging" -ForegroundColor Green

# 6. Copy Binaries
if (Test-Path $DaemonExe) {
    Copy-Item $DaemonExe -Destination (Join-Path $StagingDir "irondivid.exe") -Force
}
if (Test-Path $CliExe) {
    Copy-Item $CliExe -Destination (Join-Path $StagingDir "irondivi-cli.exe") -Force
}

# 7. Prepare AppxManifest.xml
$ManifestPath = Join-Path $MsixSourceDir "AppxManifest.xml"
$DestManifest = Join-Path $StagingDir "AppxManifest.xml"
[xml]$ManifestXml = Get-Content $ManifestPath

# Update Version
$ManifestXml.Package.Identity.Version = $Version

# Update Publisher if provided
if ($Publisher) {
    $ManifestXml.Package.Identity.Publisher = $Publisher
    Write-Host "[+] Updated Publisher to: $Publisher" -ForegroundColor Green
}

$ManifestXml.Save($DestManifest)
Write-Host "[+] Generated staging AppxManifest.xml (Version: $Version)" -ForegroundColor Green

# 8. Create MSIX Package
$MsixFileName = "IronDivi-$Version-x64.msix"
$OutputMsix = Join-Path $OutputDir $MsixFileName

Write-Host "[*] Packing MSIX package..." -ForegroundColor Cyan
& $MakeAppx pack /d $StagingDir /p $OutputMsix /nv /o
if ($LASTEXITCODE -ne 0) {
    throw "MakeAppx failed with exit code $LASTEXITCODE"
}
Write-Host "[+] Successfully created MSIX: $OutputMsix" -ForegroundColor Green

# 9. Sign package (if requested)
if ($Sign) {
    if (-not $SignTool) {
        Write-Warning "SignTool.exe not found; skipping signing."
    } else {
        if (-not $CertificatePath) {
            # Check or create self-signed test cert
            $CertThumbprint = $null
            $Subject = $ManifestXml.Package.Identity.Publisher
            $StoreCert = Get-Item "Cert:\CurrentUser\My\*" | Where-Object { $_.Subject -eq $Subject } | Select-Object -First 1

            if (-not $StoreCert) {
                Write-Host "[*] Creating self-signed certificate for '$Subject'..." -ForegroundColor Cyan
                $StoreCert = New-SelfSignedCertificate `
                    -Type Custom `
                    -Subject $Subject `
                    -KeyUsage DigitalSignature `
                    -FriendlyName "IronDivi Development Test Cert" `
                    -CertStoreLocation "Cert:\CurrentUser\My" `
                    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")
                
                # Export PFX for reuse
                $CertPfx = Join-Path $OutputDir "irondivi-test.pfx"
                $Pass = ConvertTo-SecureString -String "irondivi" -Force -AsPlainText
                Export-PfxCertificate -Cert $StoreCert -FilePath $CertPfx -Password $Pass | Out-Null
                Write-Host "[+] Exported test certificate: $CertPfx (Password: irondivi)" -ForegroundColor Green
            }
            $CertThumbprint = $StoreCert.Thumbprint
            Write-Host "[*] Signing MSIX with certificate thumbprint: $CertThumbprint" -ForegroundColor Cyan
            & $SignTool sign /fd SHA256 /sha1 $CertThumbprint $OutputMsix
        } else {
            Write-Host "[*] Signing with provided certificate: $CertificatePath" -ForegroundColor Cyan
            if ($CertificatePassword) {
                & $SignTool sign /fd SHA256 /f $CertificatePath /p $CertificatePassword $OutputMsix
            } else {
                & $SignTool sign /fd SHA256 /f $CertificatePath $OutputMsix
            }
        }

        if ($LASTEXITCODE -eq 0) {
            Write-Host "[+] MSIX package signed successfully!" -ForegroundColor Green
        } else {
            Write-Warning "SignTool returned code $LASTEXITCODE"
        }
    }
}

# 10. Generate SHA256 checksum
$Hash = (Get-FileHash -Path $OutputMsix -Algorithm SHA256).Hash.ToLower()
$HashFile = "$OutputMsix.sha256"
"$Hash  $MsixFileName" | Out-File -FilePath $HashFile -Encoding ascii
Write-Host "[+] SHA256: $Hash" -ForegroundColor Green

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Package ready:" -ForegroundColor Green
Write-Host "  MSIX:     $OutputMsix"
Write-Host "  Checksum: $HashFile"
Write-Host ""
Write-Host "For Local Testing / Sideloading:" -ForegroundColor Yellow
Write-Host "  Add-AppxPackage -Path `"$OutputMsix`""
Write-Host ""
Write-Host "For Microsoft Store Submission:" -ForegroundColor Yellow
Write-Host "  Upload `"$OutputMsix`" to Microsoft Partner Center:"
Write-Host "  https://partner.microsoft.com/dashboard/products"
Write-Host "==========================================================" -ForegroundColor Cyan
