# Securly Classroom Windows Agent — Security Research Findings

**Target**: Securly Classroom Windows agent (build identifier `1.3.10.26`, files in `Classroom/`).
**Method**: Static analysis only. .NET assemblies decompiled with `ilspycmd` 8.2.0. No runtime testing performed.
**Disclosure status**: Pre-disclosure draft for responsible reporting to `security@securly.com`.

---

## TL;DR

Three findings of practical impact, in decreasing severity:

1. **Local Privilege Escalation surface — `Everyone`-accessible .NET Remoting IPC pipe in the SYSTEM service.** The Hydra service (`MapNtSrv`, runs as `LocalSystem`) registers an `IpcServerChannel` named `UpgradeRequest` with `authorizedGroup = "Everyone"`, `exclusiveAddressUse = "False"`, and a `null` sink provider (defaults to `BinaryServerFormatterSinkProvider` at `TypeFilterLevel.Low`). Any authenticated local user can invoke `RequestUpgrade()` / `RequestDisable()` against the SYSTEM process and triggers a `BinaryFormatter` deserialization in SYSTEM context.
2. **Configuration file integrity — hardcoded AES key + IV; world-writable settings file.** The `ClassroomSettings` blob (`d6i4p.dat`) is encrypted with a static AES-CBC key/IV embedded in `Common.dll`. The `Save()` path adds an explicit `WorldSid` Read+Write ACE on the file. Tamper-detection only triggers when admin-installed "security files" are present in `system32`/`Windows`; non-admin tamper is undetected.
3. **Monitoring bypass via combined misuse of #1 and #2.** Tampering the settings file to repoint `APIServer` to an attacker-controlled host, then calling `RequestDisable()` on the Everyone-accessible pipe, causes the SYSTEM service to re-fetch enabled-state from the attacker's server and stop the monitoring `LaunchCtl`.

Plus secondary observations on the AppLife update channel, native messaging host, and QA URL leakage.

---

## 1. LPE: `Everyone`-ACL .NET Remoting IPC pipe in SYSTEM service

### Where

`WinOSServices.Service.LaunchCtlAppManager` constructor:

```csharp
// LaunchCtlAppManager.cs:87
IDictionary dictionary = new Hashtable
{
    { "portName", "UpgradeRequest" },
    { "authorizedGroup", "Everyone" },
    { "exclusiveAddressUse", "False" }
};
upgradeSrv = new IpcServerChannel(dictionary, (IServerChannelSinkProvider)null);
ChannelServices.RegisterChannel((IChannel)upgradeSrv, false);
RemotingConfiguration.RegisterWellKnownServiceType(
    typeof(UpgradeRemotingObject), "IScUpgradeRequestApi.rem", WellKnownObjectMode.Singleton);
```

`LaunchCtlAppManager` is constructed by `WinOSServices.Service.HydraManager`, which is loaded by the long-running Windows service `MapNtSrv` (`LocalSystem`). The pipe path becomes `\\.\pipe\UpgradeRequest`.

### Exposed methods

`UpgradeRemotingObject` (a `MarshalByRefObject`):

```csharp
public void RequestUpgrade() => ServiceInterface.DoManualUpdateCheck();
public void RequestDisable() => ServiceInterface.DoManualDisable();
```

`ServiceInterface.DoManualUpdateCheck()` triggers `UpdateOrDisabledChecker.UpdateCheck()`, which performs an HTTPS pull from `UpgradeServer` and feeds the result to `MonitorUpdater.DoCheck(...)`. `DoManualDisable()` calls `ForceReloadSettingsAndEnabledCheck()`, which re-reads local settings and queries `EnabledAPIClient` for student status, then starts/stops `LaunchCtl`.

### Why this matters

* `authorizedGroup = "Everyone"` translates to a pipe DACL with `BUILTIN\\Everyone` granted access. Any authenticated local user can `CreateFile` the pipe.
* The remote object is hosted in the `LocalSystem` service. Method invocation runs there.
* Because the sink provider passed to `IpcServerChannel` is `null`, the channel falls back to `BinaryServerFormatterSinkProvider` with `TypeFilterLevel.Low`. **All inbound `IMessage` payloads are deserialized via `BinaryFormatter`.** Even though the methods take no arguments, the Remoting protocol still deserializes call headers and a server-side `IMethodCallMessage`. This is a confirmed deserialization sink reachable by any local user. Microsoft has explicitly deprecated `BinaryFormatter` and `System.Runtime.Remoting` over exactly this risk; .NET Remoting deserialization has well-documented exploit gadgets (see GadgetInspector / ysoserial.net, e.g. `TextFormattingRunProperties`, `WindowsClaimsIdentity`, et al. — some work even at `TypeFilterLevel.Low`).
* `exclusiveAddressUse = "False"` plus the no-argument methods makes the pipe additionally vulnerable to **named-pipe instance squatting** and call replay if the service is restarted (a low-priv user can pre-create a same-named pipe instance if the SYSTEM channel is unregistered/torn down).

### Direct (non-deserialization) impact

Even setting the deserialization vector aside, any unprivileged local user can:
* Force update checks at will (`RequestUpgrade`) — useful for triggering vulnerable update paths or as a prerequisite to update channel attacks (see §4).
* Force the monitoring agent to re-evaluate enabled state from the (locally-configured) server (`RequestDisable`) — useful when combined with finding #2 below to immediately disable the monitor.

### Suggested fix

* Set `authorizedGroup` to `LocalSystem` or a dedicated SID; the pipe has no business being world-accessible.
* Remove `BinaryFormatter`. Migrate the upgrade IPC to `NamedPipeServerStream` + a hand-rolled JSON message protocol, or to gRPC / WCF NetNamedPipe with `DataContractSerializer`. .NET Remoting should not be carried forward.
* Set `exclusiveAddressUse` to `True` (and pass it as a `bool`, not a `string` — see §6).
* If the pipe must remain, gate every method on `WindowsIdentity.GetCurrent()` (or the Remoting `LogicalCallContext`) and reject non-SYSTEM callers explicitly, since `authorizedGroup` is enforced at pipe-bind time and cannot be relied on for per-call authorization.

### Comparable hardening already present elsewhere

The user-session forms (`FormWinHcp` for `ClassroomUserApp`, `FormLaunchAgent` for `ClassroomAgentApp`) both use `authorizedGroup = "System"`. The mistake on `UpgradeRequest` is asymmetric and looks like a copy-paste regression.

---

## 2. Hardcoded AES key/IV protects local settings; settings file is world-writable

### Where

`Common.ClassroomSettings`:

```csharp
// ClassroomSettings.cs:24-26
private static readonly string DefaultIV  = "j2tLnCxamGJ48kWrLawk3Q==";
private static readonly string DefaultKey = "AnXVsKUdQEBQj1V5dbi0wL1Poq1+FZ1NDiU3q7aFRec=";
```

The settings file is `%CommonAppData%\Securly\d6i4p.dat`, written via:

```csharp
// ClassroomSettings.cs:944 (Serialize)
GZipStream stream2 = new GZipStream(stream, CompressionMode.Compress);
AesCryptoServiceProvider aesCryptoServiceProvider = new AesCryptoServiceProvider();
ICryptoTransform transform = aesCryptoServiceProvider.CreateEncryptor(rgbKey, rgbIV);
// XML-serialize the ClassroomSettings object through the crypto stream into the gzip stream
```

### File ACL

After first write the code explicitly grants `WorldSid` Read+Write:

```csharp
// ClassroomSettings.cs:980
FileSystemAccessRule rule = new FileSystemAccessRule(
    new SecurityIdentifier(WellKnownSidType.WorldSid, null),
    FileSystemRights.Write | FileSystemRights.Read,
    AccessControlType.Allow);
accessControl.AddAccessRule(rule);
File.SetAccessControl(path, accessControl);
```

### Tamper detection

`CommunicationSettingsTampered()` compares the primary settings file against a backup in `system32\\winset15.dat`. The backup is only created when `LockDownCommunicationsSettings(true)` runs, which writes "security files" (`ant1001.inf` to `system32`, `h0000g1.dat` to `Windows`). Both writes require admin. On a non-admin user, `CommLocked == false` and `CommTampered` always returns `false`. Detection is effectively opt-in for the deployer and silently absent on standard installs.

### Field exposed in the settings blob

Includes `CustomerToken`, `AccessToken`, `APIServer`, `OAuthServer`, `UpgradeServer`, `ServerUrl`, `Udid`, `Blocklist`, `CustomBlocklist`, `Whitelist`, `BlockedModeType`, `LoggingOverride`, `IsScreenCaptureAllowed`, `IsContactAdminAllowed`, etc.

### Impact

Anyone with the agent binaries can extract the static key/IV, decrypt any `d6i4p.dat`, recover `CustomerToken`/`AccessToken` for that tenant, and — on machines where `CommLocked` is false — overwrite the file with arbitrary attacker-controlled content (different `APIServer`, empty `Blocklist`, `LoggingOverride = 0`, etc.).

Reusing a single static IV across all installs with AES-CBC is also a confidentiality smell — identical plaintext prefixes produce identical ciphertext prefixes — though the high-bit field here is the key compromise, not IV reuse.

### Suggested fix

* Stop encrypting with an embedded key. Either (a) sign-and-leave-plaintext, validating an HMAC computed with a per-machine DPAPI-protected secret, or (b) move to DPAPI (`ProtectedData.Protect` with `DataProtectionScope.LocalMachine`) for full opacity tied to the host.
* Drop the `WorldSid` write ACE. The only writer should be the SYSTEM service plus, if needed, one specific group.
* Remove the system-files-existence tamper-detection scheme; replace with HMAC validation on every load.

---

## 3. Combined chain → unauthenticated monitoring bypass and config theft

Combining #1 and #2:

1. As any local user, decrypt `%CommonAppData%\Securly\d6i4p.dat` using the embedded key/IV. Recover `CustomerToken`, `AccessToken`, `APIServer`.
2. Modify `APIServer` (and `OAuthServer` if needed) to point at an attacker-controlled HTTPS endpoint that returns `{"status":"student_disabled"}` for `GetEnabled`. Re-encrypt + write back; ACL allows it.
3. Connect to `\\.\pipe\UpgradeRequest`, invoke `UpgradeRemotingObject.RequestDisable()` over .NET Remoting. The SYSTEM service immediately re-pulls enabled-state, sees `student_disabled`, and calls `LaunchCtl.Stop()`.

End state: the monitoring/blocking subsystem is shut down without admin, without crashing the service, and without leaving an obvious "I disabled the agent" log. The 15-minute timed loop in `UpdateOrDisabledChecker.RunLoop` would normally re-check; the attacker's server can keep returning disabled.

This is the cleanest practical impact of the chain: **non-admin local user disables the monitoring agent and exfiltrates the tenant's CustomerToken/AccessToken**.

A more aggressive variant exploits the deserialization sink in #1 to gain SYSTEM RCE, but I have not built or tested a working gadget.

---

## 4. AppLife Update channel — secondary observations

`WinOSServices.Service.ClassroomUpdater.UpdaterService` constructs Kinetic Jump's `Kjs.AppLife.Update.Controller.UpdateController` with:

```csharp
UpdateLocation = "https://classroom-cloud-downloads.s3.amazonaws.com/updates/",
ApplicationId  = new Guid("c2f1ff7e-45f1-4e6a-ab28-fbbc47efc19f"),
PublicKeyToken = "<RSAKeyValue><Modulus>r+lkgCxKZIdIda0PsP2UU13M9rQdAm3lDZfb07vRQzP2p/mHMgvT75pJq1WEcVdl1zd0ypL7/XIWfh1t4EzRZUvTvMQAu2S5sxSVql8dYxFOFB+grFWJrPNACiBnRMdfyugqZbthxhs30Wdnn2jzuy0l5ceydFxIVLdgCbRWFx0=</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>",
ElevationType  = UpdateElevationType.None
```

Observations worth verifying live:

* The signing key is **RSA-1024**. Below NIST 2030 minimum (3072-bit). Not trivially factorable today, but well below current best-practice and on the wrong side of the long horizon for an installed-software trust root.
* `UpdateLocation` is an S3 path. Worth checking the bucket policy: if `s3:PutObject` is granted to anyone, an attacker uploads a manifest signed by a key they control — but signature verification will reject it as long as `PublicKeyToken` validation is enforced. The risk is real only if (a) the signature check has a bypass in this version of AppLife, or (b) the bucket allows manifest replacement and the agent doesn't check version monotonicity. (Out-of-scope for static analysis; flagging for the vendor to audit.)
* `ElevationType = None` plus the fact that `MapNtSrv` already runs as SYSTEM means any update applied via this path runs as SYSTEM. So a successful payload swap is full-trust LPE/RCE.
* `UpdaterAPIClient` and `EnabledAPIClient` set `ServicePointManager.SecurityProtocol = Tls12` but I see no certificate pinning. Both are `HttpClient` over the OS trust store. MITM requires a trusted-CA compromise on the endpoint, which is a nontrivial bar but not zero in school environments where MDM-installed root CAs are common.

---

## 5. Native messaging host has almost no surface

`ClassroomNativeHost.exe` (the Chrome native-messaging bridge listed in `manifest.json`'s `allowed_origins`) only handles two actions: `handshake` (returns assembly version) and `win_agent_capabilities` (returns a static capability list). All the actual classroom commands (`chrome_close_app`, `chrome_lock_screen`, `chrome_blocklist`, etc.) go via the listed extension IDs talking to a different service path, not the native host. Useful negative result: there's no parsing-bug pivot inside the native host itself — its `ProcessMessage` cannot reach side-effecting code paths.

(`Newtonsoft.Json` is used to deserialize into the strongly-typed `NativeHostMessage`. Json.NET `TypeNameHandling.None` is the default. No type-confusion sink visible there.)

---

## 6. Smaller items for the vendor's punch list

* **QA URL + UDID leak in code paths in `Classroom.exe`.** Hardcoded test URL containing a UDID (`3e603c19-798f-4bf6-aa42-ae92f6f488ba`) and `blockListId`:
  ```
  https://org3500.qa.techpilotlabs.com/en/agent/block?udid=3e603c19-798f-4bf6-aa42-ae92f6f488ba&...
  ```
  Looks like leftover developer/test scaffolding (`Classroom/Program.cs:462`, `759`, `1285`). Should be removed from production builds — at minimum it's a tenant-identifier disclosure and a lookup into the QA environment.
* **`exclusiveAddressUse = "False"` (string).** `IpcServerChannel` accepts `bool`, not `string`. The string `"False"` will bool.Parse correctly, but the code style implies the developer thought they were typing a literal `false`. Worth fixing for clarity and to avoid the case where parser-locale changes break it.
* **AppLauncher uses `_BypassTokenQuery`.** When set, `AppLauncher.LaunchApp` calls `CreateProcessAsUser` with `IntPtr.Zero` for `hToken` and `lpEnvironmentBlock`. With a `null` token the spawn inherits the caller's token, so a SYSTEM-context launch with `_BypassTokenQuery` produces a SYSTEM-context child. The flag is set by callers that should know what they're doing, but it is one tampered-call away from being a SYSTEM-shell primitive — worth making harder to misuse.
* **`SlingshotServer.DoLaunchModern(string cmd, string args)` → `Process.Start(cmd, args)`.** Reachable only from the SlingshotServer pipe (which has `authorizedGroup="System"`), so not directly exploitable, but if pipe ACL is ever loosened this becomes immediate command-exec.

---

## What I did

```
ilspycmd 8.2.0 → decompiled assemblies under /tmp/securly-decomp/:
  Classroom.exe, Classroom.Host.dll, ClassroomLib.dll, ClassroomNativeHost.exe,
  Common.dll, WinOSServices.dll, Kjs.AppLife.Update.Controller.dll,
  LogSender.exe, SlingshotApp.exe.
Native DyKnowHooks*.dll were not analyzed (would need Ghidra/IDA on the
PE32/PE32+ binaries — out of scope for this pass).
```

No runtime testing was performed. The Hydra service was not started, no payload was crafted, and no monitoring bypass was actually exercised. Findings are based purely on code paths visible in the decompiled output.

## Recommended disclosure path

1. Email `security@securly.com` with this report. They have a published PGP key (verify on their site).
2. Don't post POC code publicly until they've acknowledged + patched. The pipe-ACL fix is a one-line change but the deserialization removal is a refactor — give them time.
3. CVSS sketch (their assignment will be authoritative):
   * Finding #1 alone: AV:L / AC:L / PR:L / UI:N / S:C / C:H / I:H / A:H — local user → SYSTEM service interaction with deserialization sink. Likely 7.8–8.4 LPE.
   * Finding #3 (the bypass chain): AV:L / AC:L / PR:L / UI:N / S:U / C:H / I:H / A:N for the monitoring product specifically.
