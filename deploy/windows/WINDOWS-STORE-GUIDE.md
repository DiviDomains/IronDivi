# Microsoft Store Distribution Guide for IronDivi

This guide provides end-to-end instructions for packaging, testing, and publishing **IronDivi** to the **Microsoft Store (Windows App Store)** as a modern packaged desktop application (MSIX).

---

## 1. Overview & Architecture

IronDivi is packaged as a **Desktop Bridge (Centennial) MSIX Application**:
- **Package Format**: `.msix` (Windows 10 version 1809+ and Windows 11).
- **Executables**:
  - `irondivid.exe` (main full node daemon + embedded Web UI server).
  - `irondivi-cli.exe` (JSON-RPC CLI client).
- **Execution Aliases**: Both `irondivid.exe` and `irondivi-cli.exe` are registered in the Windows command prompt/PowerShell PATH upon installation.
- **Protocol Association**: Registers the `divi:` URI scheme for 1-click cryptocurrency payment handling in browsers and external applications.
- **Embedded Web UI**: Automatically binds to loopback (`127.0.0.1:8332`) and launches the default browser on desktop start.

---

## 2. Prerequisites for Publishing

1. **Microsoft Partner Center Account**:
   - Register at [partner.microsoft.com/dashboard](https://partner.microsoft.com/dashboard).
   - Enroll in the **Windows & Xbox** developer program (individual or company account).
2. **Reserve the App Name**:
   - In Partner Center -> **Apps and games** -> Click **New product** -> **MSIX or PWA app**.
   - Enter `IronDivi` and click **Reserve product name**.
3. **Obtain Your Publisher Identity**:
   - Go to Partner Center -> **Account settings** (gear icon) -> **Organization profile** -> **Legal info** -> **Developer info**.
   - Note the following three values:
     - **Package/Identity/Name**: Reserved package name (e.g. `DiviDomains.IronDivi`).
     - **Package/Identity/Publisher**: Your publisher ID string (e.g. `CN=12345678-ABCD-1234-ABCD-1234567890AB`).
     - **Package/Properties/PublisherDisplayName**: Your public developer display name (e.g. `DiviDomains` or `Divi Project`).

---

## 3. Updating the Appx Manifest

Before building the production package, ensure `deploy/windows/msix/AppxManifest.xml` matches your Partner Center identity:

```xml
<Identity
  Name="DiviDomains.IronDivi"
  Publisher="CN=YOUR-PARTNER-CENTER-PUBLISHER-ID"
  Version="0.2.9.0"
  ProcessorArchitecture="x64" />
```

> **Note**: You can also pass `-Publisher "CN=YOUR-PARTNER-CENTER-PUBLISHER-ID"` to `build-msix.ps1`, which updates the manifest during packaging automatically.

---

## 4. Building the MSIX Package

### Option A: Local Build on Windows 10/11

1. Open PowerShell in the IronDivi repository root.
2. Build the release binaries:
   ```powershell
   cargo build --release --locked --bin irondivid --bin irondivi-cli
   ```
3. Run the packaging script:
   ```powershell
   .\deploy\windows\scripts\build-msix.ps1 -Sign
   ```
   The script will:
   - Gather binaries, assets, and the manifest into a staging directory.
   - Pack with `MakeAppx.exe`.
   - Sign the package with a self-signed test certificate (for local installation).
   - Output `target\msix\IronDivi-0.2.9.0-x64.msix` and a SHA256 checksum file.

### Option B: Automated Build via GitHub Actions

1. Push a git tag (e.g. `git tag v0.2.9 && git push origin v0.2.9`) or run the **Windows Store MSIX Package** workflow manually under **Actions**.
2. Supply your Partner Center `Publisher` string in the workflow input.
3. Download the built `IronDivi-Windows-MSIX` artifact or release attachment.

---

## 5. Local Testing & Verification (Sideloading)

To verify the app locally before submitting to the Store:

1. **Install Test Certificate** (run once as Administrator):
   ```powershell
   .\deploy\windows\scripts\create-test-cert.ps1 -Publisher "CN=DiviDomains"
   ```
2. **Install the MSIX Package**:
   ```powershell
   Add-AppxPackage -Path "target\msix\IronDivi-0.2.9.0-x64.msix"
   ```
3. **Verify App Functionality**:
   - **Start Menu**: Press Win, search for `IronDivi`, and launch it.
   - **Web UI**: Verify the default browser opens to `http://127.0.0.1:8332` displaying the IronDivi node dashboard.
   - **Execution Aliases**: Open a new PowerShell terminal and run:
     ```powershell
     irondivid.exe -version
     irondivi-cli.exe getinfo
     ```
   - **Protocol Handler**: Run `start divi:D8testaddress` to verify the protocol association triggers IronDivi.
4. **Uninstall Package**:
   ```powershell
   Remove-AppxPackage -Package (Get-AppxPackage *IronDivi*).PackageFullName
   ```

---

## 6. Microsoft Store Policy Compliance & Justifications

When submitting to Microsoft Partner Center, you must fill out capability declarations and policy questionnaires:

### 1. Restricted Capability Justification (`runFullTrust`)
Microsoft requires a brief explanation for `runFullTrust`:
> **Submission Text**:
> *"IronDivi is an open-source decentralized cryptocurrency full node and wallet. It requires runFullTrust to execute native peer-to-peer TCP network communication on consensus port 51472, serve local RPC interfaces, and maintain the local embedded RocksDB blockchain ledger on disk."*

### 2. Policy 10.8 (Cryptocurrency & Financial Products)
- **Node Validation vs Mining**: IronDivi operates on Proof-of-Stake (PoS) consensus. It **does not** perform resource-intensive Proof-of-Work GPU mining. PoS validation utilizes minimal CPU cycles and does not degrade battery or hardware.
- **Non-Custodial Architecture**: IronDivi is entirely non-custodial. Private keys and HD seed phrases are generated locally, encrypted on the user's machine, and are never transmitted to third parties or remote servers.
- **Required Disclosures**: Included in the store listing (`STORE-LISTING.md`) highlighting user responsibility for seed phrase backups and market volatility risks.

### 3. Policy 10.5.1 (Privacy Policy)
Provide your privacy policy URL (e.g. `https://irondivi.com/privacy` or hosted from `docs/PRIVACY-POLICY.md`). The privacy policy explicitly affirms zero tracking, zero personal data harvesting, and complete local execution.

---

## 7. Partner Center Submission Steps

1. In **Partner Center**, navigate to your reserved **IronDivi** product.
2. Click **Start your submission**.
3. **Pricing and availability**: Set Base price to **Free**, select markets (Worldwide or desired regions).
4. **Properties**:
   - Category: `Business > Personal finance` (or `Developer tools > Utilities`).
   - Privacy Policy URL: `https://irondivi.com/privacy`.
   - Website URL: `https://irondivi.com`.
   - Support contact info: `support@irondivi.com` / GitHub issues link.
5. **Age ratings**: Complete the IARC questionnaire (Consumer utility / Financial utility -> Typically rated PEGI 3 / Everyone).
6. **Packages**:
   - Drag and drop `IronDivi-0.2.9.0-x64.msix`.
   - Partner Center will validate the package structure, manifest, and capabilities.
7. **Store listings**:
   - Copy short description, full description, features, search terms, and release notes from `deploy/windows/STORE-LISTING.md`.
   - Upload Store screenshots (1366x768 or 1920x1080 of the IronDivi WebUI dashboard, wallet, and staking tabs).
8. **Notes for certification**:
   - Paste the capability justification text from Section 6 above.
   - Mention that the app automatically launches the local WebUI interface at startup.
9. Click **Submit to the Store**.

Certification review typically takes between 24 and 72 hours. Once approved, IronDivi becomes installable directly from the Microsoft Store across all Windows 10 and Windows 11 PCs.
