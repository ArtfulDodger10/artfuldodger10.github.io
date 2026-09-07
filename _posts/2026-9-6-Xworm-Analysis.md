---
title: "XWorm — From Phishing Email to RAT"
date: 2026-09-06
description: "Static and dynamic analysis of a multi-stage XWorm V7.1 delivery chain — from a spoofed MOHRE phishing email to a fully operational RAT injected into MSBuild.exe"
tags:
  - Malware Analysis
  - Reverse Engineering
  - XWorm
  - RAT
  - .NET
  - dnSpy
  - YARA
  - Threat Intelligence
  - Blue Team
  - MITRE ATT&CK
  - Cybersecurity
  - CTI
  - PowerShell
  - JS
  - JavaScript
categories:
  - Malware Analysis
image: /assets/images/xworm_rat_minimalist.png
---

On this page

* [XWorm TL;DR](#xworm-tldr)
* [XWorm Infection Vector](#xworm-infection-vector)
* [Technical Summary](#technical-summary)
* [Technical Analysis](#technical-analysis)
   * [The Email](#the-email)
   * [Stage 1 — JavaScript Dropper](#stage-1--javascript-dropper)
      * [First Look](#first-look)
      * [Obfuscation & Encryption Scheme](#obfuscation--encryption-scheme)
      * [Static Analysis](#static-analysis)
      * [Dynamic Analysis](#dynamic-analysis)
   * [Stage 2 — PowerShell Loader](#stage-2--powershell-loader)
   * [Stage 3 — XWorm V7.1 RAT](#stage-3--xworm-v71-rat)
      * [Configuration Extraction](#configuration-extraction)
      * [C2 Communication](#c2-communication)
      * [Command Dispatcher](#command-dispatcher)
      * [Core Capabilities](#core-capabilities)
      * [Persistence — Three Mechanisms](#persistence--three-mechanisms)
* [Conclusion](#conclusion)
* [IoCs](#iocs)
* [YARA Rule](#yara-rule)
* [MITRE ATT&CK](#mitre-attck)
* [References](#references)

---

## XWorm TL;DR

XWorm is a feature-rich Remote Access Trojan sold as Malware-as-a-Service on underground forums since 2022. It is builder-based — any buyer receives a panel and a generator producing customized payloads, which makes attribution to a specific threat actor rarely possible. In this sample, the payload arrived through a phishing email impersonating the UAE Ministry of Human Resources, delivered via a multi-stage chain starting with a JavaScript dropper and ending with XWorm V7.1 injected into MSBuild.exe. The previous sample I analyzed from the same family used a VBScript downloader — that analysis is documented [here](https://artfuldodger10.github.io/posts/XWorm-RAT-Malware-Analysis/). Unlike that sample where the C2 was dead before the payload could be retrieved, this chain was fully intact and analyzed end to end.

---

## XWorm Infection Vector

The attack arrives as a spoofed email impersonating the UAE Ministry of Human Resources & Emiratisation (MOHRE), one of the most authoritative government bodies in the region for employment and labor affairs. The email is addressed to `help@banquemisr.ae` and carries the subject line _"Contract / عقد العمل"_, presenting itself as an official employment contract notification. The body is brief and bilingual, Arabic and English, instructing the recipient to retrieve contract number `MB308992219AE` from the attachment. No malicious link, no suspicious phrasing. Just an authority figure telling you your contract is ready.

The sender display name reads _Ministry of Human Resources & Emiratisation_, but the actual sending address is `ek@chaek.ru`, routed through `mail.lpltd.ru` (`77.232.184.7`), a Russian mail server with no relation to any UAE government infrastructure. What makes this more deliberate is the spoofed `References:` header, which points to `@DXBMAIL03.mol.local`, an internal Exchange server hostname belonging to the UAE Ministry of Labour. The attacker either had prior access to a legitimate email thread from that domain, or fabricated the header knowing the target would recognize it as authentic internal correspondence. Either way, it is a calculated trust-building move.

![Phishing email](/assets/images/x/email.png)

The attachment `MB308992219AE.r12` is declared as `application/zip` in the mail headers but is in fact part 13 of a multi-volume RAR archive. The victim receives only this fragment, the remaining parts, `.r00` through `.r11` and the base archive, were either delivered through a separate channel or retrieved after initial interaction. Once the full archive is reconstructed and extracted, a single JavaScript file is revealed: `MB308992219AE.js`, named identically to the contract number to maintain the illusion of legitimacy.

![WinRAR archive reconstruction](/assets/images/x/winrar.png)

---

## Technical Summary

<ins>**Configuration Extraction:**</ins> XWorm stores its entire configuration as AES-encrypted, Base64-encoded strings inside a static `Settings` class. The encryption key is derived from the mutex string using MD5, making the mutex the single key to the entire configuration. Decrypted, the configuration reveals the C2 server at `109.248.150.234:1012`, the AES communication key, the C2 splitter, the install path, and the USB spreading filename.

<ins>**C2 Communication:**</ins> XWorm communicates with its operator over a raw TCP connection, with all traffic encrypted using AES and delimited by the splitter `<Xwormmm>`. On execution, XWorm profiles the infected host and sends a registration beacon to the C2 panel before awaiting operator commands.

<ins>**Core RAT Capabilities:**</ins> Here lies the bulk of its functionality. Once connected to C2, XWorm hands the operator full control over the infected machine. The available capabilities are:

- Remote shell via `cmd.exe`
- Screen capture
- Keylogging
- Clipboard monitoring and cryptocurrency address hijacking
- File manager, upload, download, delete
- Process manager, enumerate and terminate
- USB spreading
- Remote .NET assembly loading

<ins>**Persistence:**</ins> XWorm establishes persistence through three independent mechanisms, a registry run key, a scheduled task configured to run every minute, and a startup folder LNK shortcut. The binary copies itself to `%AppData%\bin.exe` and ensures execution survives reboots and process termination.

---

## Technical Analysis

### Stage 1 — JavaScript Dropper

#### First Look

`MB308992219AE.js` arrives as the final payload of the reconstructed RAR archive, named deliberately to match the contract number from the email. At 200.60 KB it is far larger than any legitimate JavaScript contract document would be — the bulk of that size is occupied by five large encoded blob variables carrying the encrypted payload and keys. At the time of analysis, 26 out of 50 security vendors on VirusTotal flagged it as malicious.

![VirusTotal detection — JavaScript dropper](/assets/images/x/VT_js.png)

Opening the file reveals heavily obfuscated JavaScript disguised as a legitimate web analytics component. Every sensitive string is stored as an encrypted hex blob and decrypted on demand at runtime, nothing meaningful is visible in the static file without running the decryption pipeline first.

#### Obfuscation & Encryption Scheme

All function and variable names are replaced with randomized identifiers. Every sensitive string is passed through a custom decryption function `__hdl_4f()` at the moment it is needed, leaving no plaintext indicators in the static file. The decryption pipeline is multi-layered:

```
Hex blob
    → __key_5ab()     custom decoder using _0x1046b1 as charset
    → IV extraction   first 16 bytes
    → __mem_ff2()     custom key derivation producing two 32-byte subkeys
    → __tag_d7()      pre-decryption whitening XOR pass
    → __dat_fc()      AES-256 key schedule
    → __ctx_1d()      AES-256-CBC block decryption (14 rounds)
    → __dat_225()     ChaCha20-seeded Fisher-Yates substitution table
    → __mem_d9()      ChaCha20-style stream cipher XOR pass
    → __tmp_b9()      PKCS7 unpadding
    → plaintext
```

The hardcoded 32-byte base key `__ctx_3f` is embedded directly in the JS. Beyond string encryption, execution is gated behind two state machine counters, `__sec_4cb` and `__ref_22e`, that simulate legitimate widget activity before the payload is allowed to fire. `__sec_4cb` must reach 2 as the fake library data loads, and `__ref_22e` must reach 2 with at least 150 fake query rows accumulated. Only when both conditions are satisfied does the real code execute.

The five blob variables carry the entire attack:

| Variable    | Role                                        |
| ----------- | ------------------------------------------- |
| `_0x70b5b5` | Encrypted Stage 2 PowerShell script         |
| `_0x4e45f3` | Encryption key                              |
| `_0x1046b1` | Custom hex charset                          |
| `_0x777de5` | `__DLL__` placeholder — encoded loader blob |
| `_0xd8faa8` | `__PLD__` placeholder — encoded XWorm blob  |

#### Static Analysis

The state machine gates and the encrypted blobs make this file resistant to automated analysis. To extract the payload statically, the full decryption pipeline was reimplemented in Node.js, replicating the `simulateClick()` logic exactly outside the browser environment.

![Node.js decryptor output](/assets/images/x/dec.js%20output%20terinal.png)

Running the decryptor against the five blob variables produced a 63,271-character PowerShell script, Stage 2. The output opens with `function Read-StreamConfig`, confirming a clean decryption. The script was redirected to disk for further analysis.

#### Dynamic Analysis

To validate the static findings and observe the full execution behavior without running anything on the host, the deobfuscated JS was loaded in an isolated Chrome DevTools environment. The analysis was conducted entirely within the browser sandbox — no files written to disk, no processes spawned.

The malware's execution gates were bypassed by forcing both state counters to 2 before the JS loaded. The real `FileSystemObject` and `Shell.Application` ActiveX objects were replaced with JavaScript stubs that mirror the real API surface but log every call to console instead. The `ShellExecute` call was patched out and replaced with a console log capturing the exact command that would have executed.

With the gates bypassed and the decryption pipeline run directly in the console, `__obj_14` was populated with 138,292 characters of plaintext, the same PowerShell script the static approach produced, confirming both methods independently.

Calling `__cnt_d7a()` triggered the full execution path. The following files were intercepted before they would have been written to disk:

<div style="display:flex;gap:12px;flex-wrap:wrap;">
<img src="/assets/images/x/fwf.png" alt="First blob written to disk">
<img src="/assets/images/x/swf.png" alt="Second blob written to disk">
</div>

*Two blobs being written to the same random folder*

The main script (`.ps1`) and what it does:

**Step 1 — Blob 1 decoded from disk, decrypted via XOR-rotate-AES pipeline, and loaded as a .NET assembly into the PowerShell process memory:**

<div style="display:flex;gap:12px;flex-wrap:wrap;">
<img src="/assets/images/x/New%20folder/k1%20v1%20c1.png" alt="Key 1 / IV 1 / Cipher 1">
<img src="/assets/images/x/New%20folder/mount_f.png" alt="Mount function">
<img src="/assets/images/x/New%20folder/expand-decryption.png" alt="Expand decryption">
</div>

**Step 2 — Blob 2 decoded and decrypted into an in-memory byte array; its exact format is determined by the loaded assembly, not the PowerShell script:**

<div style="display:flex;gap:12px;flex-wrap:wrap;">
<img src="/assets/images/x/k2%20v2%20c2.png" alt="Key 2 / IV 2 / Cipher 2">
<img src="/assets/images/x/expand-decryption.png" alt="Expand decryption">
</div>

**Step 3 — `AC1_1.OrderWorkflow.ProcessFulfillment` called:**

![ProcessFulfillment invocation](/assets/images/x/step3,%20.png)

**Step 4 — MSBuild path resolved:**

![MSBuild path](/assets/images/x/step%204.png)

**Step 5 — Console hidden via two independent mechanisms:**

`FreeConsole()` detaches from the console; `ShowWindow(..., 0)` hides the window. The PowerShell script dynamically constructs P/Invoke declarations for `FreeConsole`, `GetConsoleWindow`, and `ShowWindow`, enabling interaction with the Windows console without directly exposing the API names in plaintext. The loader calls `FreeConsole()` to detach from the console and subsequently obtains the console window handle using `GetConsoleWindow()` and calls `ShowWindow(..., 0)`, where `0` corresponds to `SW_HIDE`, to conceal the window from the user.

<div style="display:flex;gap:12px;flex-wrap:wrap;">
<img src="/assets/images/x/freeconsole.png" alt="FreeConsole call">
<img src="/assets/images/x/show_window.png" alt="ShowWindow call">
</div>

Every execution generates a fresh 8-character folder name, a 4-character hex session tag, and randomized filenames drawn from a rotating prefix pool — `dat_`, `cfg_`, `run_`, `svc_`, `tmp_`. Filesystem IOCs are useless for detection. The only stable artifacts are the hardcoded crypto keys embedded in the JS.

<div style="display:flex;gap:12px;flex-wrap:wrap;">
<img src="/assets/images/x/fwf.png" alt="First write — run 1">
<img src="/assets/images/x/first%20write%20file.png" alt="First write — run 2">
</div>

*Different folder names across two runs*

**Step 6 — The intercepted launcher revealed the exact execution command, and both scripts clean up after themselves:**

<div style="display:flex;gap:12px;flex-wrap:wrap;">
<img src="/assets/images/x/cmd.png" alt="Execution command">
<img src="/assets/images/x/batch%20script.png" alt="Batch script self-deletion">
</div>

32-bit PowerShell is used deliberately — `SysWOW64\powershell.exe` rather than the 64-bit equivalent — consistent with the x86 payload that follows. After execution, both the `.cmd` launcher and the PowerShell script independently clean up all written files. The launcher self-deletes via `@(goto) 2>nul & del "%~f0"`. By the time any forensic tool examines the filesystem, nothing remains.

---

### Stage 2 — PowerShell Loader

The launcher executes `svc_82497_95cb.ps1` via 32-bit PowerShell with `-w h -nop -ExecutionPolicy Bypass`. The script's first task is decoding the two blobs from disk using `Read-StreamConfig`, a custom base52 decoder that processes input in 10-character chunks, each decoding to 7 bytes using a lookup table built from A–Z and a–z. The result is a raw byte array ready for decryption.

Decryption is handled by `StreamHelper.Expand()`, compiled at runtime via `Add-Type`. It applies three sequential transforms to each blob:

```
input bytes
    → XOR with IV byte at position (i & 15)
    → rotate right by (k[(i+7) & 31] % 7) + 1 bits
    → XOR with k[i % kl] and k[(i+17) & 31]
    → AES-CBC PKCS7 decrypt (key=k, iv=iv)
```

The keys and IVs are hardcoded in plaintext inside the PowerShell script — no derivation required:

```
k1: 2F EF CA F8 36 D3 4A A0 7E 83 12 96 01 8F A1 75
    5F CA 46 B7 AD 30 2E C8 84 E8 6A 18 80 1E AE E7
v1: B1 F6 F7 C7 26 0B F2 61 2F 17 CA 01 EB 23 6F E7

k2: 6D E9 01 6D 6E 1A 50 1B 7C C3 35 55 8B 07 9D 70
    EE DD 27 00 16 D2 80 26 85 CA E0 FF FA 70 C9 84
v2: 87 CE 9E 81 BD D8 81 71 B1 DD 0F 53 2B 42 41 12
```

Blob 1 decrypts to a .NET loader assembly, loaded directly into the PowerShell process memory via `AppDomain.CurrentDomain.Load(byte[])` — never written to disk as a DLL. Blob 2 decrypts to the XWorm payload bytes, passed directly to the loaded assembly.

The loader then reflectively resolves and invokes `AC1_1.OrderWorkflow.ProcessFulfillment(string, byte[])` on the in-memory assembly, passing the hardcoded MSBuild path and the XWorm bytes. The injection target is not decided at runtime — it is hardcoded:

```powershell
$tp = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe"
```

Joe Sandbox confirmed process hollowing — `PowerShell.exe` injects the XWorm PE into `MSBuild.exe` at base address `0x6D0000`. `MSBuild.exe` is spawned as the host process and the XWorm image is mapped into its address space, replacing its legitimate code. From this point XWorm runs entirely within the `MSBuild.exe` process context — all network connections, registry writes, and persistence operations originate from a trusted Microsoft binary.

![Process hollowing — Joe Sandbox confirmation](/assets/images/x/hollowing.png)

The `#XLOADER` comment immediately below marks an alternate execution mode where the current process path is used instead — a builder artifact indicating this script is generated by a tool with multiple output configurations.

![MSBuild path selection](/assets/images/x/msbuild.png)

After execution, both blob files and the PowerShell script are deleted via `Remove-Item -Force -EA 0`. The console is suppressed via `FreeConsole()` and `ShowWindow(hwnd, 0)` before the injector fires.

---

### Stage 3 — XWorm V7.1 RAT

#### First Look

`stage3_payload.bin` is a 32-bit .NET assembly, 35.50 KB. 56 out of 69 security vendors on VirusTotal flagged it as malicious.

![VirusTotal detection — XWorm payload](/assets/images/x/VT%20xworm.png)

#### Configuration Extraction

![Encrypted configuration strings](/assets/images/x/encrypted%20config.png)

XWorm stores its configuration as AES-encrypted, Base64-encoded strings inside the `Settings` class.

![Decryption algorithm](/assets/images/x/dec%20algo.png)

`AlgorithmAES.Decrypt()` derives the AES key by computing `MD5(UTF-8(mutex))` — producing a 16-byte digest — then building a 32-byte key with two `Array.Copy` calls:

```csharp
Array.Copy(array2, 0, array, 0,  16);  // digest → positions 0–15
Array.Copy(array2, 0, array, 15, 16);  // digest → positions 15–30
```

The second copy starts at position 15, overwriting `array[15]` with `digest[0]`. The resulting 32-byte key is:

```
digest[0..14] | digest[0] | digest[1..15]
```

Position 15 holds `digest[0]`, not `digest[15]`. This one-byte overlap is deliberate — it makes the key non-standard while keeping derivation simple and reproducible from the mutex alone. Anyone replicating the config extractor must implement this exact overlap or produce a wrong key.

![Main AES routine](/assets/images/x/main%20aes.png)

To extract the configuration statically, the key derivation and decryption routine were reimplemented in Python using the plaintext mutex as the only input.

![Python config extractor output](/assets/images/x/d.png)

The decrypted configuration reveals the C2 at `109.248.150.234:1012`, with `<V7PV7PV7PV7PV7P>` as the AES communication key and `<Xwormmm>` as the stream splitter. Both are default values from the XWorm V7.1 builder, unchanged by the operator.

The C2 at `109.248.150.234` is hosted by SIA RixHost (AS203557) in Zwolle, Netherlands, a data center and web hosting provider. The IP has one prior abuse report from December 2024 flagging a webmail attack, with a current abuse confidence of 0%. No other malware families have been publicly linked to this address at the time of analysis, suggesting either a freshly provisioned or low-activity C2 node.

#### C2 Communication

XWorm communicates over raw TCP using a length-prefixed framing protocol. Every message on the wire follows this structure:

```
[ ASCII length string ][ 0x00 null byte ][ AES-128-ECB ciphertext ]
```

The receiver reads one byte at a time until the null terminator, parses the declared length, then reads exactly that many bytes before dispatching the payload to the command handler.

![Network connection to 109.248.150.234:1012](/assets/images/x/network%20connection%20109.png)

Triage sandbox confirmed repeated outbound connections to `109.248.150.234:1012` from the XWorm process — consistent with the reconnection loop firing every 3–10 seconds on failed connection attempts.

On connection, XWorm immediately sends a registration beacon — `INFO` — carrying the victim's hardware ID, username, OS version, group tag, CPU, GPU, RAM, antivirus products, webcam presence, UAC level, and idle time. The operator's panel receives a full victim profile before issuing a single command.

![INFO beacon method](/assets/images/x/info%20method.png)

The heartbeat fires every 10–15 seconds — randomized to avoid fixed-interval network signatures — reporting the currently focused window title and idle time to the operator.

#### Command Dispatcher

All incoming traffic is handled by `Read()`, which decrypts each packet, splits on `<Xwormmm>`, and dispatches on the first token. The full command set:

<div style="display:flex;gap:12px;flex-wrap:wrap;">
<img src="/assets/images/x/read1.png" alt="Read() — part 1">
<img src="/assets/images/x/read2.png" alt="Read() — part 2">
<img src="/assets/images/x/read3.png" alt="Read() — part 3">
<img src="/assets/images/x/read4.png" alt="Read() — part 4">
<img src="/assets/images/x/read5.png" alt="Read() — part 5">
</div>

*`Read()` function — full command dispatcher*

#### Core Capabilities

**Remote Shell**

`RunShell` passes the operator's command string directly to a hidden `cmd.exe` process. Full interactive shell over the encrypted C2 channel.

![RunShell implementation](/assets/images/x/runshell.png)

**Drop and Execute**

`RunDisk()` writes a received payload to `%TEMP%\<6-char random><extension>` and executes it. `.ps1` payloads are launched with `-ExecutionPolicy Bypass` automatically.

![Drop and execute](/assets/images/x/drop%20and%20exec.png)

**Reflective Loading**

`Memory()` loads a received .NET assembly directly into the malware's process memory via `AppDomain.CurrentDomain.Load(byte[])` — no file ever touches disk.

![Reflective loading](/assets/images/x/ref%20loading.png)

**Screenshot Capture**

The `$Cap` command captures the primary screen at 16bpp, downsizes to 256×156 JPEG, GZip-compresses it, and sends it as `#CAP` to the C2 panel. Designed for low-bandwidth live monitoring.

![Screenshot capture](/assets/images/x/screenshot%20capture.png)

**Process Monitor**

`Monitoring()` takes a comma-separated keyword list from the operator and scans all running process window titles every second. When a target keyword is detected, a bank name, crypto wallet, anything, it sends an alert to C2. Used for targeted surveillance.

![Process monitoring](/assets/images/x/monitoring.png)

**HTTP Flood**

`TD()` spawns 20 concurrent threads per round, each sending an HTTP POST with a randomized User-Agent to the target. Rounds fire every 5 seconds for the configured duration. Controlled by `StartDDos` / `StopDDos`.

![HTTP flood](/assets/images/x/http%20flood.png)

**Hosts File Manipulation**

`Hosts` reads and exfiltrates the full hosts file. `Shosts` overwrites it with operator-supplied content — silently redirecting any domain on the victim machine.

![Hosts file manipulation](/assets/images/x/hosts%20manipulatoin.png)

**Plugin System**

XWorm supports a modular plugin architecture. Plugins are .NET assemblies pushed from C2, loaded reflectively, and cached in the registry between sessions. The plugin dispatcher supports execution, credential recovery, process injection, UAC bypass, and ransomware encryption and decryption — all gated behind the `ENC`/`DEC` state flag to prevent double-encryption.

<div style="display:flex;gap:12px;flex-wrap:wrap;">
<img src="/assets/images/x/plugin1.png" alt="Plugin system — part 1">
<img src="/assets/images/x/plugin2.png" alt="Plugin system — part 2">
</div>

#### Anti-Analysis & Evasion

XWorm prevents the host from sleeping via `SetThreadExecutionState` with `ES_CONTINUOUS | ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED` — keeping the machine and display awake indefinitely while it runs.

Windows Defender exclusions are added via PowerShell `-ExecutionPolicy Bypass` if the process has admin privileges — covering both the running executable and the install path, by path and by process name.

<div style="display:flex;gap:12px;flex-wrap:wrap;">
<img src="/assets/images/x/anti%201%20preventsleep.png" alt="Anti-analysis — prevent sleep">
<img src="/assets/images/x/anti%202%20exclusion.png" alt="Anti-analysis — Defender exclusion">
</div>

#### Persistence — Three Mechanisms

**1. Scheduled Task** (runs every minute):

```csharp
processStartInfo.Arguments = "/create /f /RL HIGHEST /sc minute /mo 1 /tn \"<name>\" /tr \"<path>\"";
// If not admin, same command without /RL HIGHEST
```

`/sc minute /mo 1` fires every minute, making persistence far more aggressive — the malware is relaunched every 60 seconds regardless of whether a new logon occurs. Admin runs additionally get `/RL HIGHEST` for elevated execution.

**2. Registry Run Key:**

```
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\<InstallStr name> = "<InstallDir>\<InstallStr>"
```

**3. Startup Folder Shortcut:**

```
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\bin.lnk
```

After creating the shortcut, `Helper.fileStream = new FileStream(lnk, FileMode.Open)` opens and holds a file handle on the `.lnk`, keeping it locked so it cannot be deleted by security tools without first closing the handle. `Uninstaller.UNS()` explicitly calls `Helper.fileStream.Close()` before attempting deletion.

The uninstaller cleanly removes all four artifacts in sequence: the persistence copy, the registry run key, the scheduled task, and the startup shortcut — then self-deletes via a temporary batch file with a 3-second timeout.

<div style="display:flex;gap:12px;flex-wrap:wrap;">
<img src="/assets/images/x/per%201.png" alt="Persistence — scheduled task">
<img src="/assets/images/x/per%202.png" alt="Persistence — registry run key">
<img src="/assets/images/x/per%203.png" alt="Persistence — startup shortcut">
</div>

*Three independent persistence mechanisms*

---

## Conclusion

XWorm V7.1 is a capable and actively maintained remote access trojan distributed as a commodity builder on underground forums. This sample arrived through a carefully constructed phishing email impersonating the UAE Ministry of Human Resources & Emiratisation — a government authority with direct relevance to the target's employment status. The lure required no interaction beyond opening the attachment, and the delivery chain was designed to leave nothing on disk by the time the payload was running.

The JavaScript dropper is the most technically sophisticated component of the chain. Its multi-layer encryption scheme, state machine execution gates, and filesystem interception make it resistant to both static analysis and automated sandboxing. The PowerShell loader that follows is compact and purpose-built — it decrypts, loads, and injects with no unnecessary complexity. XWorm itself is the final reward: a full-featured RAT with remote shell, keylogging, screen capture, clipboard hijacking, USB spreading, a plugin system that extends to ransomware, and three independent persistence mechanisms that make removal non-trivial.

The operator made no meaningful customization to the builder defaults — the AES key, splitter, and group tag are all factory values. That points to a low-effort deployment. The delivery tells a different story. Spoofing an internal UAE Ministry of Labour Exchange hostname in the `References:` header is calculated and researched — not something a careless actor does. The payload was left untouched. The lure was not.

---

## IoCs

| No. | Description | Value |
| --- | ----------- | ----- |
| 1 | Phishing attachment | `8f6b44db0884d056ba1ea591679fa5ce6cdebb53c4ee6e925e21400ff6d3535e` |
| 2 | JavaScript dropper | `81f93dc173ad6b2d7592447c7910f70df668b1a06f7c2fcce08188a99d38dcb3` |
| 3 | XWorm payload / `bin.exe` | `9ef39965263531f35203eea0a1924181264cf6d7f3832d939cd532d5fad77a2d` |
| 4 | Startup shortcut (`bin.lnk`) | `2175df45893a994d82868e142b7d591a4c08efa764a53d9f45ec0fc32b4e5582` |
| 5 | XWorm C2 | `109.248.150.234:1012` |
| 6 | Mutex | `aGO284VKfQVe8Vup` |
| 7 | Sending server | `77.232.184.7` |

---

## YARA Rule

```ruby
rule xworm_v71 : rat
{
    meta:
        description = "Detects XWorm V7.1 payload and delivery chain"
        author      = "Artful Dodger"
        date        = "2026-09"
        hash        = "9ef39965263531f35203eea0a1924181264cf6d7f3832d939cd532d5fad77a2d"

    strings:
        $x1 = "AlgorithmAES" ascii wide
        $x2 = "aGO284VKfQVe8Vup" ascii wide
        $x3 = "Xwormmm" ascii wide
        $x4 = "AC1_1.OrderWorkflow" ascii wide
        $x5 = "ProcessFulfillment" ascii wide

        $ps1 = "Read-StreamConfig" ascii
        $ps2 = "StreamHelper" ascii
        $ps3 = "SysWOW64\\WindowsPowerShell" ascii wide
        $ps4 = "(goto) 2>nul & del" ascii

        $k1 = { 2F EF CA F8 36 D3 4A A0 7E 83 12 96
                01 8F A1 75 5F CA 46 B7 AD 30 2E C8
                84 E8 6A 18 80 1E AE E7 }

    condition:
        (3 of ($x*)) or
        (3 of ($ps*)) or
        ($k1)
}
```

---

## MITRE ATT&CK

| Tactic | ID | Technique | Evidence |
| ------ | -- | --------- | -------- |
| Initial Access | T1566.001 | Spearphishing Attachment | MOHRE lure email with RAR attachment |
| Execution | T1059.007 | JavaScript | `MB308992219AE.js` executed by victim |
| Execution | T1059.001 | PowerShell | `-w h -nop -ExecutionPolicy Bypass` |
| Execution | T1059.003 | Windows Command Shell | `RunShell` command, `cmd.exe` execution |
| Execution | T1047 | Windows Management Instrumentation | Host profiling via WMI in beacon |
| Execution | T1053.005 | Scheduled Task | `schtasks /create /sc minute /mo 1` |
| Persistence | T1547.001 | Registry Run Keys / Startup Folder | Run key + startup LNK + scheduled task |
| Persistence | T1053.005 | Scheduled Task | Every-minute persistence mechanism |
| Defense Evasion | T1140 | Deobfuscate/Decode Files | AES-256-CBC + ChaCha20 runtime decryption |
| Defense Evasion | T1036.005 | Masquerading | JS disguised as analytics widget |
| Defense Evasion | T1070.004 | File Deletion | Self-deleting CMD, PS cleanup, `Remove-Item` |
| Defense Evasion | T1055.012 | Process Hollowing | XWorm injected into `MSBuild.exe` |
| Defense Evasion | T1127.001 | Trusted Developer Utilities | `MSBuild.exe` as injection host |
| Defense Evasion | T1562.001 | Impair Defenses | Windows Defender exclusions via PowerShell |
| Defense Evasion | T1027 | Obfuscated Files or Information | Encrypted config, runtime string decryption |
| Defense Evasion | T1620 | Reflective Code Loading | `AppDomain.CurrentDomain.Load(byte[])` |
| Defense Evasion | T1112 | Modify Registry | Plugin cache stored in registry |
| Collection | T1056.001 | Keylogging | XWorm keylogger module |
| Collection | T1113 | Screen Capture | `$Cap` command, GDI `CopyFromScreen` |
| Collection | T1115 | Clipboard Data | Clipboard monitor + crypto clipper |
| Collection | T1560.002 | Archive via Library | GZip compression before exfiltration |
| Discovery | T1082 | System Information Discovery | OS, CPU, GPU, RAM via WMI |
| Discovery | T1033 | System Owner/User Discovery | Username, hostname in beacon |
| Discovery | T1057 | Process Discovery | `Monitoring()` process window scanner |
| Discovery | T1012 | Query Registry | Plugin cache registry queries |
| Discovery | T1083 | File and Directory Discovery | File manager capability |
| Discovery | T1518 | Software Discovery | Antivirus enumeration via `SecurityCenter2` |
| Lateral Movement | T1091 | Replication Through Removable Media | USB spreading as `USB.exe` |
| Command and Control | T1095 | Non-Application Layer Protocol | Raw TCP to `109.248.150.234:1012` |
| Command and Control | T1573.001 | Encrypted Channel: Symmetric | AES-128-ECB for all C2 traffic |
| Command and Control | T1571 | Non-Standard Port | Port `1012` |
| Command and Control | T1132.001 | Data Encoding: Standard Encoding | Base64 for binary payloads |
| Impact | T1491 | Defacement | Hosts file manipulation via `Shosts` |
| Impact | T1498 | Network Denial of Service | HTTP flood via `StartDDos` |

---

## References

1. ANY.RUN interactive analysis — XWorm payload  
   `https://app.any.run/tasks/3c61aa71-87f8-4e16-9af0-7b1fe34fecbe/`
2. Joe Sandbox full report  
   `https://www.joesandbox.com/analysis/1965848/0/html`
3. Aziz Haddadi — XWorm V3.1 Analysis (structural reference for version comparison)  
   `https://github.com/aziz-haddadi/XWorm-V3.1-Analysis`
4. Triage Sandbox Behavioral Analysis  
   `https://tria.ge/260904-ptndks1bnb/behavioral2`
5. AbuseIPDB IP Check  
   `https://www.abuseipdb.com/check/109.248.150.234`
6. MITRE ATT&CK  
   `https://attack.mitre.org`