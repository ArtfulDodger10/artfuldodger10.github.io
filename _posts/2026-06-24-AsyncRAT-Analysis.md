---
title: "AsyncRAT Analysis"
date: 2026-06-24
description: "A comprehensive reverse engineering and malware analysis of AsyncRAT v0.5.8. Covers configuration decryption, PBKDF2/AES cryptography, RSA signature validation, mutex creation, anti-analysis techniques, encrypted TLS C2 communications, dynamic behavior, and detection strategies."
tags:
  - Malware Analysis
  - Reverse Engineering
  - AsyncRAT
  - RAT
  - .NET
  - dnSpy
  - YARA
  - Threat Intelligence
  - Blue Team
  - MITRE ATT&CK
  - Cybersecurity
  - CTI
categories:
  - Malware Analysis
image: /assets/images/asyncrat_minimalist_rat.png
---


## Background

AsyncRAT is an open-source Remote Access Trojan written in C# and originally published on GitHub in 2019 under the guise of a legitimate remote administration tool. The source being public is both its strength and its weakness from a detection standpoint — anyone can grab it, recompile it, and tweak it, which means no two samples are identical. So that's where the analysis starts.



---

## File Identification

| Field | Value |
|---|---|
| File Name | `3dbaf616dcaacfcf66909b7a3404d1536f9e0d230b3b59934f1ccc6fe3e20554.exe` (internal: WinRar) |

| Size | 52 KB |
| MD5 | `0BE5324BA4C2F648CEE646E91135728F` |
| SHA1 | `19905D50384DB33546B8D86CDBC9B0864A3ECD43` |
| SHA256 | `3DBAF616DCAACFCF66909B7A3404D1536F9E0D230B3B59934F1CCC6FE3E20554` |
| Type | PE32 executable (GUI), Intel 80386, Mono/.NET assembly |

---

## Part 1 — Basic Static Analysis

### DIE 

![Cl]({{"/assets/images/AsyncRAT/DIE.png"}}) | ![C]({{"/assets/images/AsyncRAT/DIE entropy.png"}}) 


**PE Header Fields of Interest:**

| Field | Value |
|---|---|
| MachineType | Intel 386 |
| Compile Timestamp | 2023-10-16 21:40:53 UTC |
| Sections | 3 |
| CodeSize | 45,568 bytes |
| EntryPoint | 0xd09e |
| Subsystem | Windows GUI |
| Linker Version | 8 |

The builder is probably old stock — the binary was compiled years before this sample showed up.

**Version Info Spoofing:**

The binary carries metadata impersonating WinRAR:

| Field | Spoofed Value |
|---|---|
| CompanyName | RarLab |
| FileDescription | WinRar |
| FileVersion | 7.5.6.1 |
| OriginalFileName | WinRar |
| ProductName | WinRar |

Pretending to be WinRAR is a cheap trick, but it works — most people won't look twice at something that claims to be an archiving tool.

---

### Python PE Script

![Cl]({{"/assets/images/AsyncRAT/my basic rule.png"}})
A standard AsyncRAT sample (unpacked) will show a single import: `mscoree.dll` with `_CorExeMain`. That's the .NET runtime bootstrapper — the actual functionality lives in the managed IL code, invisible to traditional import analysis. If packed, expect elevated entropy across all sections.

---

### String Analysis


##### I've got really some interesting strings

###### 1. `c2.skyupdragon.io.exe`

This string appears to be the filename used when the malware installs or copies itself into the victim machine. 

---

###### 2. `%AppData%`


References the Windows AppData directory, it's a common location used by malwares to store files because users typically have write permissions there.


---

###### 3. `schtasks /create /f /sc onlogon /rl highest`

Indicates use of Windows Scheduled Tasks for persistence. The task is configured to execute whenever a user logs on and requests the highest available privileges.

---

###### 4. `CreateSubKey`, `OpenSubKey`, `SetValue`, `DeleteValue`

Registry manipulation functions used to create, modify, or remove registry entries.

---

###### 5. `Select * from AntivirusProduct`

###### 6. `\root\SecurityCenter2`


WMI query used to enumerate installed antivirus products on the victim system.


---

###### 7. `VirtualBox`


Reference to Oracle VirtualBox virtualization software.

---

###### 8. `SbieDll.dll`


DLL associated with Sandboxie.

---

###### 9. `CheckRemoteDebuggerPresent`

Windows API used to determine whether a debugger is attached to the process.

---

###### 10. `EnterDebugMode`

Windows debugging-related API.


---

###### 11. `RtlSetProcessIsCritical`

Native Windows API capable of marking a process as critical.

---

###### 12. `SslStream`

###### 13. `AuthenticateAsClient`

###### 14. `TcpClient`

###### 15. `NetworkStream`

.NET networking classes used to establish encrypted communications with a command-and-control (C2) server.

---

###### 16. `AesCryptoServiceProvider`

###### 17. `CreateEncryptor`

###### 18. `CreateDecryptor`

###### 19. `Rfc2898DeriveBytes`

###### 20. `HMACSHA256`

Cryptographic functions used for encryption, decryption, key derivation, and message authentication.


---

###### 21. `GZipStream`

.NET compression library.


---

###### 22. `WebClient`

###### 23. `DownloadString`


Functions capable of downloading content from remote servers.


---

###### 24. `savePlugin`

###### 25. `sendPlugin`

###### 26. `Plugin.Plugin`


References to a plugin management system.


---

###### 27. `GetForegroundWindow`

###### 28. `GetWindowText`

Windows APIs used to obtain information about the currently active window.

---

###### 29. `get_UserName`

###### 30. `get_MachineName`

###### 31. `get_OSVersion`

###### 32. `ComputerInfo`

###### 33. `DriveInfo`


System information gathering functions.



---

###### 34. Large Base64-Encoded Blobs

Examples:

```
sqvoun5N0fakkFX5...
exJQ76+nZgGExV8...
0mdzA7mKOCVaujOC...
```

Large encoded data blocks embedded within the executable.


## Part 2 — Basic Dynamic Analysis (ANY.RUN + Triage)

### ANY.RUN Report

**the sandbox run was limited**

![Cl]({{"/assets/images/AsyncRAT/anyrun general.png"}}) | ![ C]({{"/assets/images/AsyncRAT/anyrun process.png}}) 

**Sandbox Environment:** Windows 10 Professional (build 19044, 64-bit)
**Verdict:** Malicious
**Detection:** AsyncRAT confirmed via YARA

**Process Information:**

| Field | Value |
|---|---|
| PID | 3144 |
| Path | `C:\Users\admin\AppData\Local\Temp\3DBAF616DCAACFCF66909B7A3404D1536F9E0D230B3B59934F1CCC6FE3E20554.exe` |
| Parent | `explorer.exe` |
| User | admin |
| Integrity Level | MEDIUM |
| Company (spoofed) | RarLab |

The sample ran as a single process — no child processes were spawned in the sandbox window. The behavior graph shows a flat tree: just the one executable running directly from Temp.

**Behavioral Indicators:**

| Severity | Indicator |
|---|---|
| Malicious | ASYNCRAT detected via YARA |
| Info | Reads machine GUID from registry |
| Info | Reads computer name |
| Info | Checks supported system languages |

The language check is the System Language Discovery technique (T1614.001) — AsyncRAT uses this to infer victim geography, often to avoid infecting systems in certain regions.

**Registry Activity:**

Total 564 events, all reads, zero writes. In the sandbox window, persistence was not written — either `AutoRun: false` suppressed it, or the sandbox time limit was hit before that stage executed.

**Files Activity:**

No files dropped. Consistent with `install: false` in the extracted config.

**Extracted Malware Configuration (ANY.RUN):**

| Field | Value |
|---|---|
| Family | AsyncRAT |
| Version | 0.5.8 |
| Botnet | xTeam |
| C2 Hosts | `hubscore.io`, `www.hubscore.io` |
| Ports | 8090, 7080, 443, 80 |
| Mutex | `rxUf9crL1mff` |
| AutoRun | false |
| Install | false |
| InstallFolder | `%AppData%` |
| InstallFile | `c2.skyupdragon.io.exe` |
| BSoD | true |
| AntiVM | true |
| AES Key | `42ef5c76d82323e50a62f28fb34230e4b2871810f45eb66dc04e0fcd765968a6` |
| Salt | `bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941` |
| AES Plaintext | `uboPUIGxH1wbTAls9Pf7vNmiOAHEUlnt` |

The `BSoD: true` and `AntiVM: true` flags confirm that both the process-criticality trick and the virtual machine detection routines are active in this build.

---

### Network Activity
![Cl]({{"/assets/images/AsyncRAT/anyrun config.png"}})

**Malicious DNS / Connection:**

![Cl]({{"/assets/images/AsyncRAT/dns.png"}}) | ![ C]({{"/assets/images/AsyncRAT/connections.png}}) 

| PID | Process | IP | Domain | Reputation |
|---|---|---|---|---|
| 3144 | `WinRar.exe` | `172.67.139.209:7080` | `hubscore.io` | **Malicious** |

The sample connected to `hubscore.io` via Cloudflare infrastructure (`172.67.139.209`, `104.21.94.206`) — the operator is hiding behind Cloudflare's proxy. The connection was made on port 7080, one of the four configured C2 ports.

**DNS resolution for `hubscore.io`** returned two IPs, both flagged malicious:
- `172.67.139.209`
- `104.21.94.206`

All other network activity (21 HTTP requests, remaining 54 TCP connections) belongs to Windows system processes (`svchost.exe`, `SIHClient.exe`) making Microsoft update and telemetry calls — these are sandbox baseline noise, not malware activity.

**IDS Alert:**
![Cl]({{"/assets/images/AsyncRAT/alerts.png"}})
`Class:`   A Network Trojan was detected
`Message:` MALWARE [ANY.RUN] Win32/Common RAT related JA3 hash observed
`PID:`     3144

The JA3 fingerprint matched a known RAT signature. This is expected — .NET's SslStream uses a fixed cipher suite ordering, so every AsyncRAT sample produces basically the same TLS handshake fingerprint.

---

### Triage Report

![Cl]({{"/assets/images/AsyncRAT/trg10.png"}}) | ![ C]({{"/assets/images/AsyncRAT/trg config.png}}) 


**Score:** 10/10
**Tags:** asyncrat, rat, xteam, discovery

Triage's config extractor produced the same fields as ANY.RUN, confirming the extraction is consistent. The `aes.plain` field (`uboPUIGxH1wbTAls9Pf7vNmiOAHEUlnt`) is the plaintext master password used with PBKDF2 to derive the actual AES key — this matches the derivation scheme found in static analysis.

Triage also flagged:
- **Async RAT payload** — confirmed binary signature
- **Unsigned PE** — no Authenticode signature, as expected for malware
- **System Language Discovery** (T1614.001)
- **Suspicious use of AdjustPrivilegeToken** — privilege manipulation during execution


---

## Part 3 — Advanced Static Analysis (dnSpy)

![Cl]({{"/assets/images/AsyncRAT/main.png"}})

The sample is obfuscated. Class and method names are replaced with random alphanumeric strings. Navigation requires following behavior rather than names.

---

### Class `NmxKiSWCMEb` — Configuration Loader

This is the entry point for configuration handling. Two key methods were identified.

**Method `VkUXWPRuNNeIB` — Configuration Decryptor**

![Cl]({{"/assets/images/AsyncRAT/method vku.png"}})


This method is responsible for loading, decrypting, and validating the malware's configuration before execution continues. The sequence:

1. Decodes an embedded key from Base64
2. Instantiates the cryptographic engine
3. Decrypts each configuration field individually
4. Loads the embedded X.509 certificate
5. Verifies configuration integrity via RSA signature

The malware will not proceed past this point unless every validation step passes. This protects the operator's infrastructure — a tampered or extracted config will be rejected.

**Method `TPobVYcTtGvhWE` — RSA Signature Verifier**

![Cl]({{"/assets/images/AsyncRAT/TPo.png"}})


Uses `RSACryptoServiceProvider.VerifyHash()` with SHA-256 to validate the configuration blob's authenticity. The public key comes from the embedded X.509 certificate. If the hash doesn't match the stored `Server_Signature`, execution terminates.

**Embedded Certificate Usage:**

The X.509 certificate (`Cert1` in the extracted config) is used purely as a key container — not for TLS. The workflow is:

**Decrypt certificate data**
→ Create X509Certificate2 object
→ Extract RSA public key
→ Use public key to verify config signature

The certificate is dated June 18, 2026 (created shortly before the sample was submitted), and is self-signed with the CN `AsyncRAT Server`. This is standard AsyncRAT builder output.

---

### Class `kawzoBCaSQU` — Cryptographic Engine

![Cl]({{"/assets/images/AsyncRAT/kawzo class.png"}})


This class handles all encryption and decryption of configuration data. It ensures the config is unreadable in static analysis without runtime key derivation.

**Key Derivation (PBKDF2):**
`Algorithm:`  Rfc2898DeriveBytes (PBKDF2-HMAC-SHA1)
`Password:`   uboPUIGxH1wbTAls9Pf7vNmiOAHEUlnt  (plaintext from config)
`Salt:`       bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941
`Iterations:` 50,000
`Output key:` 42ef5c76d82323e50a62f28fb34230e4b2871810f45eb66dc04e0fcd765968a6

50,000 iterations — enough to make offline cracking painful.

**AES Configuration:**
`API:`       AesCryptoServiceProvider
`KeySize:`   256 bits
`BlockSize:` 128 bits
`Mode:`      CBC
`Padding:`   PKCS7


**HMAC Integrity Protection:**

compares both values byte by byte before proceeding.

The full decryption flow:

**Receive encrypted blob**
→ Compute HMAC-SHA256 over ciphertext
→ Compare against stored HMAC  (bAUEvYzAtIBIjDAF)
→ If match: decrypt with AES-256-CBC
→ If mismatch: abort

---

### Class `hHcUBVwURarBo` — Mutex Manager

![Cl]({{"/assets/images/AsyncRAT/mutex creation.png"}})

**Method `lFlKIJmClcgz()` — Mutex Creation**

Creates a named system mutex to enforce a single instance of the malware. If the mutex `rxUf9crL1mff` already exists when the process starts, the method returns `false` and execution stops — preventing double infection and conflicting C2 connections.

**Method `xWBgFTueRllD()` — Mutex Cleanup**

Calls `Close()` on the mutex handle during shutdown. Mutex gets closed on shutdown so the next run starts clean.

---

## Execution Chain

Based on the combined static and dynamic analysis, the execution flow is:

```plaintext
Main()
  │
  ├─ Delay Execution          (initial sleep to evade sandbox timeouts)
  │
  ├─ Load Encrypted Config    (NmxKiSWCMEb.VkUXWPRuNNeIB)
  │
  ├─ Verify RSA Signature     (NmxKiSWCMEb.TPobVYcTtGvhWE)
  │
  ├─ Load Embedded Cert       (X509Certificate2 → public key extraction)
  │
  ├─ Create Mutex             (hHcUBVwURarBo.lFlKIJmClcgz → "rxUf9crL1mff")
  │
  ├─ AntiVM Checks            (VirtualBox, SbieDll.dll, CheckRemoteDebuggerPresent)
  │
  ├─ System Reconnaissance    (username, machine name, OS, AV products via WMI)
  │
  ├─ Installation Routine     (copy to %AppData%\c2.skyupdragon.io.exe — if install=true)
  │
  ├─ Persistence Routine      (schtasks /create /f /sc onlogon /rl highest)
  │
  ├─ Mark Process Critical    (RtlSetProcessIsCritical → BSoD on kill)
  │
  ├─ Initialize Components    (keylogger, screenshot, plugin loader, C2 client)
  │
  └─ C2 Loop                  (TcpClient → SslStream → AES-encrypted comms → hubscore.io:7080)
```

## IOCs

**Hashes:**

| Type | Value |
|---|---|
| MD5 | `0BE5324BA4C2F648CEE646E91135728F` |
| SHA1 | `19905D50384DB33546B8D86CDBC9B0864A3ECD43` |
| SHA256 | `3DBAF616DCAACFCF66909B7A3404D1536F9E0D230B3B59934F1CCC6FE3E20554` |

**Network:**

| Type | Value |
|---|---|
| C2 Domain | `hubscore.io` |
| C2 Domain | `www.hubscore.io` |
| C2 IP | `172.67.139.209` |
| C2 IP | `104.21.94.206` |
| Ports | 8090, 7080, 443, 80 |
| Install Reference | `c2.skyupdragon.io` |

**Host:**

| Type | Value |
|---|---|
| Mutex | `rxUf9crL1mff` |
| Install Path | `%AppData%\c2.skyupdragon.io.exe` |
| Persistence | Scheduled task via `schtasks /create /f /sc onlogon /rl highest` |
| AES Key | `42ef5c76d82323e50a62f28fb34230e4b2871810f45eb66dc04e0fcd765968a6` |
| PBKDF2 Salt | `bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941` |

---

## MITRE ATT&CK Mapping

| Technique | ID | Notes |
|---|---|---|
| Remote Access Tool | T1219 | AsyncRAT core capability |
| System Information Discovery | T1082 | Username, machine name, OS, drives |
| System Language Discovery | T1614.001 | Language check at startup |
| Boot/Logon Autostart — Scheduled Task | T1053.005 | `schtasks /create /f /sc onlogon` |
| Boot/Logon Autostart — Registry Run | T1547.001 | Registry API calls present |
| Virtualization/Sandbox Evasion | T1497 | VirtualBox, Sandboxie, debugger checks |
| Encrypted Channel | T1573.001 | AES-256-CBC over TLS |
| Ingress Tool Transfer | T1105 | `WebClient.DownloadString` |
| Process Discovery | T1057 | AV enumeration via WMI |
| Query Registry | T1012 | Machine GUID, computer name reads |
| Obfuscated Files | T1027 | Encrypted config, Base64 blobs |

---

## References

- ANY.RUN Report: https://app.any.run/tasks/2fa8f14b-f2ac-45d4-9b72-18e1f595e383
- Malpedia: https://malpedia.caad.fkie.fraunhofer.de/details/win.asyncrat
- CISA Advisory AA23-025A: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a
- AsyncRAT Source (reference): https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp