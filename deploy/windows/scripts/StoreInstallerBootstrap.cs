// SPDX-License-Identifier: AGPL-3.0-only
// IronDivi Windows Store MSIX Bootstrapper
// Trusts the DiviDomains MSIX signing certificate in LocalMachine\TrustedPeople
// and LocalMachine\Root, then opens the MSIX package in the native Windows
// App Installer (Microsoft Store MSIX installer UI).

using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Windows.Forms;

[assembly: AssemblyTitle("IronDivi Windows Installer")]
[assembly: AssemblyDescription("IronDivi Full Node & Wallet — Windows Store MSIX Installer")]
[assembly: AssemblyCompany("DiviDomains")]
[assembly: AssemblyProduct("IronDivi")]
[assembly: AssemblyVersion("0.2.9.0")]
[assembly: AssemblyFileVersion("0.2.9.0")]

namespace IronDiviInstaller
{
    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            try
            {
                if (args.Length >= 2 && args[0] == "--install-cert")
                {
                    InstallCertificate(args[1]);
                    return 0;
                }

                string stagingDir = Path.Combine(Path.GetTempPath(), "IronDivi-Store-Installer");
                Directory.CreateDirectory(stagingDir);

                string cerPath = Path.Combine(stagingDir, "IronDivi.cer");
                string msixPath = Path.Combine(stagingDir, "IronDivi-x64.msix");

                ExtractResource("IronDivi.cer", cerPath);
                ExtractResource("IronDivi.msix", msixPath);

                if (!IsCertificateTrusted(cerPath))
                {
                    if (IsAdministrator())
                    {
                        InstallCertificate(cerPath);
                    }
                    else
                    {
                        ProcessStartInfo psi = new ProcessStartInfo
                        {
                            FileName = Assembly.GetExecutingAssembly().Location,
                            Arguments = "--install-cert \"" + cerPath + "\"",
                            Verb = "runas",
                            UseShellExecute = true
                        };
                        using (Process p = Process.Start(psi))
                        {
                            if (p == null)
                            {
                                return 1;
                            }
                            p.WaitForExit();
                            if (p.ExitCode != 0)
                            {
                                MessageBox.Show(
                                    "Could not register the IronDivi publisher certificate (exit code " + p.ExitCode + ").",
                                    "IronDivi Installer",
                                    MessageBoxButtons.OK,
                                    MessageBoxIcon.Error
                                );
                                return p.ExitCode;
                            }
                        }
                    }
                }

                // Launch the MSIX in the native Windows App Installer (Store-style GUI)
                ProcessStartInfo openMsix = new ProcessStartInfo
                {
                    FileName = "explorer.exe",
                    Arguments = "\"" + msixPath + "\"",
                    UseShellExecute = true
                };
                Process.Start(openMsix);
                return 0;
            }
            catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
            {
                // User cancelled UAC prompt
                MessageBox.Show(
                    "Administrator approval is needed once to trust the IronDivi publisher certificate before installing.",
                    "IronDivi Installer",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information
                );
                return 1223;
            }
            catch (Exception ex)
            {
                MessageBox.Show(
                    "IronDivi Installer encountered an error:\n\n" + ex.Message,
                    "IronDivi Installer",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error
                );
                return 1;
            }
        }

        private static void ExtractResource(string resourceName, string outputPath)
        {
            Assembly asm = Assembly.GetExecutingAssembly();
            using (Stream s = asm.GetManifestResourceStream(resourceName))
            {
                if (s == null)
                {
                    throw new InvalidOperationException("Missing embedded resource: " + resourceName);
                }
                using (FileStream fs = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.Read))
                {
                    s.CopyTo(fs);
                }
            }
        }

        private static bool IsAdministrator()
        {
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
        }

        private static bool IsCertificateTrusted(string cerPath)
        {
            X509Certificate2 cert = new X509Certificate2(cerPath);
            string thumbprint = cert.Thumbprint;
            if (string.IsNullOrEmpty(thumbprint))
            {
                return false;
            }
            return StoreHasThumbprint(StoreName.TrustedPeople, thumbprint)
                && StoreHasThumbprint(StoreName.Root, thumbprint);
        }

        private static bool StoreHasThumbprint(StoreName storeName, string thumbprint)
        {
            X509Store store = new X509Store(storeName, StoreLocation.LocalMachine);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection found = store.Certificates.Find(
                    X509FindType.FindByThumbprint,
                    thumbprint,
                    false
                );
                return found.Count > 0;
            }
            catch
            {
                return false;
            }
            finally
            {
                store.Close();
            }
        }

        private static void InstallCertificate(string cerPath)
        {
            X509Certificate2 cert = new X509Certificate2(cerPath);
            foreach (StoreName storeName in new[] { StoreName.TrustedPeople, StoreName.Root })
            {
                X509Store store = new X509Store(storeName, StoreLocation.LocalMachine);
                try
                {
                    store.Open(OpenFlags.ReadWrite);
                    store.Add(cert);
                }
                finally
                {
                    store.Close();
                }
            }
        }
    }
}
