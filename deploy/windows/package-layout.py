"""
package-layout.py — Cross-platform layout validator and preparation tool
for IronDivi Windows App Store (MSIX) distribution (stdlib-only).

Validates AppxManifest.xml, verifies all visual assets, and stages the layout.
"""

import os
import shutil
import xml.etree.ElementTree as ET

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
MSIX_SRC = os.path.join(SCRIPT_DIR, "msix")
MANIFEST_PATH = os.path.join(MSIX_SRC, "AppxManifest.xml")
ASSETS_DIR = os.path.join(MSIX_SRC, "Assets")

REQUIRED_BASE_ASSETS = [
    "StoreLogo.png",
    "Square44x44Logo.png",
    "Square150x150Logo.png",
    "Wide310x150Logo.png",
    "SplashScreen.png",
    "Square71x71Logo.png",
    "iron-mark.ico"
]

def check_manifest():
    print("[*] Validating AppxManifest.xml...")
    if not os.path.exists(MANIFEST_PATH):
        raise FileNotFoundError(f"Manifest missing: {MANIFEST_PATH}")
    
    tree = ET.parse(MANIFEST_PATH)
    root = tree.getroot()
    
    # Check namespaces
    ns = {
        "m": "http://schemas.microsoft.com/appx/manifest/foundation/windows10",
        "uap": "http://schemas.microsoft.com/appx/manifest/uap/windows10",
        "rescap": "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities",
        "desktop": "http://schemas.microsoft.com/appx/manifest/desktop/windows10",
    }
    
    identity = root.find("m:Identity", ns)
    if identity is None:
        raise ValueError("Missing <Identity> in manifest")
    
    name = identity.attrib.get("Name")
    publisher = identity.attrib.get("Publisher")
    version = identity.attrib.get("Version")
    arch = identity.attrib.get("ProcessorArchitecture")
    
    print(f"    Package Name:     {name}")
    print(f"    Publisher:        {publisher}")
    print(f"    Version:          {version}")
    print(f"    Architecture:     {arch}")
    
    # Check capabilities
    capabilities = root.find("m:Capabilities", ns)
    if capabilities is None:
        raise ValueError("Missing <Capabilities> in manifest")
    
    has_full_trust = False
    for child in capabilities:
        if child.attrib.get("Name") == "runFullTrust":
            has_full_trust = True
    
    if not has_full_trust:
        raise ValueError("Missing required <rescap:Capability Name='runFullTrust' />")
    print("    Capabilities:     runFullTrust verified (Desktop Bridge enabled)")
    
    # Check applications
    app = root.find(".//m:Application", ns)
    if app is None:
        raise ValueError("Missing <Application> in manifest")
    exe = app.attrib.get("Executable")
    entry = app.attrib.get("EntryPoint")
    print(f"    Executable:       {exe} (EntryPoint: {entry})")
    
    return root

def check_assets():
    print("\n[*] Validating Visual Assets...")
    if not os.path.exists(ASSETS_DIR):
        raise FileNotFoundError(f"Assets dir missing: {ASSETS_DIR}")
    
    missing = []
    for asset in REQUIRED_BASE_ASSETS:
        p = os.path.join(ASSETS_DIR, asset)
        if not os.path.exists(p):
            missing.append(asset)
        else:
            size = os.path.getsize(p)
            print(f"    ✓ {asset:<26} ({size:,} bytes)")
    
    if missing:
        raise FileNotFoundError(f"Missing required assets: {', '.join(missing)}")
    
    all_files = os.listdir(ASSETS_DIR)
    print(f"    Total asset variants in Assets/: {len(all_files)}")

def stage_layout(dest_dir, bin_dir=None):
    print(f"\n[*] Staging packaging layout in {dest_dir}...")
    if os.path.exists(dest_dir):
        shutil.rmtree(dest_dir)
    os.makedirs(dest_dir, exist_ok=True)
    
    # Copy manifest
    shutil.copy2(MANIFEST_PATH, os.path.join(dest_dir, "AppxManifest.xml"))
    
    # Copy assets
    shutil.copytree(ASSETS_DIR, os.path.join(dest_dir, "Assets"))
    
    # Copy binaries if present
    if bin_dir and os.path.isdir(bin_dir):
        for b in ["irondivid.exe", "irondivi-cli.exe"]:
            src_b = os.path.join(bin_dir, b)
            if os.path.exists(src_b):
                shutil.copy2(src_b, os.path.join(dest_dir, b))
                print(f"    ✓ Staged binary: {b}")
            else:
                print(f"    ! Binary not found (expected for non-Windows host): {src_b}")
    else:
        print("    ℹ Staged manifest & assets only (binaries staged during build)")

def main():
    print("=" * 60)
    print("  IronDivi Windows MSIX Packaging Layout Validator")
    print("=" * 60)
    
    check_manifest()
    check_assets()
    
    staging_target = os.path.join(REPO_DIR, "target", "msix-layout")
    stage_layout(staging_target)
    
    print("\n[+] Verification passed successfully! Layout is ready for MakeAppx packaging.")

if __name__ == "__main__":
    main()
