---
title: "Lumma Campaign C++ Crypter"
date: 2026-10-11
description: "Reversing a multi-stage chain: an obfuscated C++ crypter hollows MSBuild.exe to run a dropper, which installs a .NET crypto clipper and a second crypter carrying Lumma Stealer."
tags:
  - lumma stealer
  - lummac2
  - infostealer
  - crypto clipper
  - crypter
  - process hollowing
  - msbuild
  - api hashing
  - murmurhash2
  - rc4
  - chacha20
  - config extraction
  - yara
  - malware analysis
  - reverse engineering
categories: [Malware Analysis]
image: /assets/images/lumma/rust/burgundy.png
---

# AIO Checker: a fake checker tool that drops a crypto clipper and Lumma Stealer

**On this page**
- [AIO Checker TL;DR](#aio-checker-TL;DR)
- [AIO Checker Infection Vector](#aio-checker-infection-vector)
- [Technical Summary](#technical-summary)
- [Technical Analysis](#technical-analysis)
  - [First look & the outer crypter](#first-look--the-outer-crypter)
  - [Process hollowing into MSBuild](#process-hollowing-into-msbuild)
  - [The dropper](#the-dropper)
  - [The crypto clipper](#the-crypto-clipper)
  - [The second crypter and Lumma Stealer](#the-second-crypter-and-lumma-stealer)
  - [Lumma C2 configuration](#lumma-c2-configuration)
  - [Lumma C2 communication](#lumma-c2-communication)
  - [Lumma information stealing](#lumma-information-stealing)
  - [Anti-analysis](#anti-analysis)
- [Conclusion](#conclusion)
- [Limitations / open questions](#limitations--open-questions)
- [MITRE ATT&CK](#mitre-attck)
- [IoCs](#iocs)
- [YARA Rules](#yara-rules)
- [References](#references)

---

## AIO Checker TL;DR

In this post I analyze a RAR archive called `AIO Checker 8.10.10.rar`. The name makes it look like an "all-in-one" checker tool, but the executable inside is the start of a chain of five malicious programs. They come in four kinds:

- a 64-bit **crypter** A wrapper that hides an encrypted program and runs it in memory. It appears twice in the chain.
- a **dropper** A program whose only job is to write other programs to disk and start them.
- a .NET **crypto clipper** Malware that watches the clipboard and swaps cryptocurrency addresses for the attacker's.
- **Lumma Stealer**, An infostealer collects data from the infected machine (browser data, wallets, host details) and uploads it to the attacker's server.

![Figure(0)](/assets/images/lumma/rust/VT.png)

## AIO Checker Infection Vector

AIO Checker is spread mostly inside the cracking and credential-stuffing community, where people look for free checkers and are used to AV detections. Because of this, there are many known delivery methods. Only a few of them are stated below:

- Shared in Telegram channels and Discord servers focused on cracking and combo lists.
- Posted on cracking forums as a “free” or “cracked” version of a paid checker.
- Hosted on fake GitHub repositories that look like legit open-source checkers.
- YouTube tutorials with the download link in the video description.
- Trojanized copies of legit checkers that work normally while stealing data in the background.

---

| file | what it is |
|---|---|
| `AIO Checker 8.10.10.exe` | the malware (outer crypter) |
| `dnscmmc.dll`, `elshyph.dll` | Windows 8.1 system DLLs, judging by their version info. No stage references them by name, and the EXE never loaded them in my run. I think they are filler to make the folder look like a real tool. |
| `README.txt` | 20 bytes, containing only `hxxps://t[.]me/hitbase` |

I don't know the purpose of the Telegram link, and I did not visit it.

The infection seems to need the victim to run the EXE manually. In my run I started it from Explorer.

![Figure(1): Contents of the AIO Checker archive: the EXE, two decoy Windows DLLs and a README with a Telegram link.](/assets/images/lumma/rust/fig%201.png)


## Technical Summary

<ins>**Outer crypter (`AIO Checker 8.10.10.exe`, x64):**</ins> An obfuscated C/C++ program with no imports beyond KERNEL32. It finds the Windows APIs it needs by name hash, using a slightly modified MurmurHash2 (seed 707). It decrypts the next stage from a section named `.jss` with RC4 and a 10-byte hard-coded key, then starts the 32-bit `MSBuild.exe` from the .NET Framework and most likely hollows it with that payload. Its version info is copied from Microsoft's `mobsync.exe`, and it has a broken signature entry.

<ins>**Dropper (x86, runs inside MSBuild):**</ins> It decrypts two embedded programs with RC4 and a 40-byte key, writes them to `%APPDATA%\<10 random chars>.exe` and runs both.

<ins>**Crypto clipper (.NET):**</ins> Built from a project folder named "ShinobuClipper-master". It copies itself to the Startup folder as `svhost.exe` and replaces copied crypto addresses with one of 13 attacker wallets. I saw the swap happen in my run. It has no network code.

<ins>**Second crypter:**</ins> The same build as the outer crypter, with the same RC4 key. It starts a second MSBuild and most likely hollows it with Lumma Stealer.

<ins>**Lumma C2 configuration:**</ins> 9 C2 entries (8 unique domains) encrypted with ChaCha20, plus a Steam profile that is likely a backup way to find the C2.

<ins>**Lumma C2 communication:**</ins> HTTPS POST requests to `/xane`, with the build ID `37d7c3a0bc391b79b770bb89c2e2e1a3` sent as `uid`. In my run the sequence was a check-in, then an upload that is likely encrypted or compressed, then a final POST.

<ins>**Information stealing:**</ins> The code contains strings for Chromium and Firefox data, crypto wallets, Steam, Outlook and Windows Mail, Notepad++ files and a `System.txt` host profile. It also has code to read the clipboard and take screenshots.

<ins>**Anti-analysis:**</ins> Strings built on the stack, code that breaks the decompiler, a hypervisor-vendor check and a direct-syscall stub.

---

## Technical Analysis

### First look & the outer crypter

The EXE is a 64-bit PE built with the Microsoft C/C++ runtime . Here are the first things I noticed:

- Its only imports come from KERNEL32. There are no network, crypto or registry imports.
- The PE timestamp is 2025-04-30 14:44:14 UTC. Timestamps can be forged, so I treat it as a hint only.
- Two sections called `.jss` take up about 89% of the file. They are byte-identical, each 0x12D400 bytes, with entropy 7.999. Entropy that close to 8 means the data is encrypted or compressed. I don't know why there are two copies.

![Figure(2): Section table of the outer EXE: two identical high-entropy `.jss` sections.](/assets/images/lumma/rust/fig%202.png)

The code is heavily obfuscated. Two techniques show up in the WinMain, the API resolver, the RC4 routine and the core function:

- **Control-flow flattening:** the normal if/else structure is replaced by one big state machine.
- **Opaque predicates:** conditions that always give the same result but are hard to see through, such as `x*(x-1) & 1 == 0`.

WinMain also calls three functions that do nothing useful. They make no API calls and write nothing to global data. I assume they are there to make the program look like a normal C++ application and to dilute signatures.

The real work starts in a thread (`0x140011350`) that WinMain creates with `CreateThread` (the call is at `0x140012BA5`).

**API hashing**

The crypter doesn't import the APIs it needs for injection. It finds them at runtime with a resolver at `0x140001BA0`, which takes a module base and a 32-bit hash:

1. It walks the module's export table, one name at a time.
2. It copies each name into a `std::string` and hashes it with `0x140001000`, using seed **707 (0x2C3)**.
3. When the hash matches, it looks up the ordinal and the function RVA and returns the address. It doesn't handle forwarded or ordinal-only exports.

The resolver is flattened like the rest of the code, but underneath it's a plain export-table walk.

The hash function is MurmurHash2 with one change. When the name length isn't a multiple of 4, the last 1–3 bytes are handled differently:

```text
standard MurmurHash2:  h ^= tail;  h *= m
this build:            h ^= tail * m        (m = 0x5BD1E995)
```

This cost me some time. My first Python version used the standard algorithm and matched only 5 of the 12 hashes. Those 5 names all happen to be 12 or 16 characters long, so they never reach the tail code. After I read the tail in the decompiler and fixed my version, all 12 hashes resolved, each to exactly one export.


All 12 are resolved from `KERNEL32.DLL`, which the crypter finds by walking the PEB's loaded-module list and comparing each name with `wcscmp`. They are resolved one after another in the core function (`0x14000D5D1`–`0x14000D6B7`). My script is in the repo as `tools/murmur2_variant.py`.

![Figure(3): The 12 hashes passed to the API resolver.](/assets/images/lumma/rust/fig%203.1.png)|![Figure(3)](/assets/images/lumma/rust/fig%203.2.png)


**Payload decryption**

The function at `0x1400028D0` is plain RC4: the standard key setup and keystream generation, decrypting in place. The 10-byte key is built on the stack as a qword plus a word:

```text
RC4 key (10 bytes): 92 54 67 56 42 11 36 4D BB 01
built at 0x14000D6E7 (qword 0x4D36114256675492) and 0x14000D6F4 (word 0x01BB), key length 0xA at 0x14000D719
```

Decrypting `.jss` with this key gives a complete 32-bit PE: the dropper, 1,233,920 bytes, which fills the section exactly. I confirmed this in two ways. First, I decrypted the real section in Python and checked the hash. Second, I called the crypter's own RC4 routine in x64dbg on the section, and it produced `MZ` at the start of the buffer.

The RC4 routine also contains a sleep. Its key-setup helper (`0x140003090`, called with the value `2`) leads to `std::this_thread::sleep_for`. I didn't check whether the `2` means seconds or milliseconds, or why it's there.

![Figure(4): The RC4 key on the stack, and .jss data before and after the crypter's own RC4 routine (two debugger sessions, so the addresses differ).](/assets/images/lumma/rust/fig%204.1.png) *Decryption in IDA* | ![Figure(4)](/assets/images/lumma/rust/before%20rc4.png) *Before* | ![Figure(4)](/assets/images/lumma/rust/after%20rc4.png) *After*


**Fake identity**

The crypter's version-info resource is a copy of Windows `mobsync.exe`. The PE also has a broken Authenticode entry:

- The security directory (file offset 0x175800, size 0x2628) points into the encrypted `.jss` data instead of a certificate.
- The file ends in a 9,728-byte block of zeros.
- The PE checksum is valid.

My reading is that the builder copies a signed Microsoft binary's metadata onto the stub, zero-fills the certificate area and recomputes the checksum. I'm moderately confident about this. The second crypter in the chain shows the same pattern, and the Windows Amcache inventory recorded both crypter EXEs with the publisher "microsoft corporation".

![Figure(5): The crypter's file properties claim to be Microsoft's mobsync.exe.](/assets/images/lumma/rust/mobsync.png) | ![fig](/assets/images/lumma/rust/fig%205.png)


### Process hollowing into MSBuild

**Process hollowing** is a way to run malicious code under the name of a legitimate program ([MITRE ATT&CK T1055.012](https://attack.mitre.org/techniques/T1055/012/)). The loader:

1. starts a legitimate program in a suspended state,
2. replaces its memory with the malicious program,
3. points the thread at the new entry point, and
4. resumes it.

This is what the crypter does, call by call, as it appears in the disassembly of the core function (`0x140003DA0`):

1. `CreateProcessA` with flag `4` (`CREATE_SUSPENDED`) and no command line.
2. `GetThreadContext` / `Wow64GetThreadContext` on the new thread, then `ReadProcessMemory` of 4 or 8 bytes, most likely the target's image base from its PEB.
3. `VirtualAllocEx` at the **payload's own preferred image base**, with size `SizeOfImage`, `MEM_COMMIT|MEM_RESERVE` and `PAGE_EXECUTE_READWRITE` (`0x40`).
4. `WriteProcessMemory` three times: the PE headers, then each section, then the new image base into the PEB.
5. `SetThreadContext` / `Wow64SetThreadContext` (in a standard hollowing loader, this points the thread at the payload's entry point), then `ResumeThread`.

There is no unmap step. `NtUnmapViewOfSection` isn't resolved or imported anywhere, so the crypter never removes MSBuild's own image. It just asks for memory at the payload's preferred base address.

If `VirtualAllocEx` returns NULL, the crypter calls `TerminateProcess(hProcess, 0)` on that MSBuild. The most likely reason for a NULL is that the address is already in use inside the new process. There are three `VirtualAllocEx` call sites:

- **`0x14000D2F0`:** I followed the state machine block by block from that `TerminateProcess` straight back to `CreateProcessA`. There is no retry counter, so it keeps starting new MSBuild processes until the allocation works.
- **`0x14000C95D`:** this one also calls `TerminateProcess` on failure, but I couldn't follow its state machine all the way back because it runs through two more nested dispatchers.

The binary has three `CreateProcessA` call sites, but only one (`0x14000C5CF`) is live. The other two can only be reached through opaque predicates that never take that branch, so they are copies added by the obfuscator.

I ran the sample twice, and the two runs show this loop from both sides:

- **First run:** the EXE created **3** instances of `C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe` within 115 ms, each with no command-line arguments. Only one of them shows any activity afterwards. The other two left no events in Procmon or Sysmon.
- **Second run:** it created only **one** MSBuild, and that one went on to run the dropper.

This fits the retry loop, because a process count that changes between runs matches allocations that fail only some of the time. It isn't proof, since I didn't see the failed `VirtualAllocEx` calls themselves. In both runs this is the 32-bit MSBuild, which matches the 32-bit payload, and the EXE exited with status 0 a few seconds after it started (about 4.7 s in the first run).

I didn't watch the injection itself happen. Every call and argument above comes from the disassembly.

![Figure(6): First run: the crypter starts three 32-bit MSBuild.exe processes within 115 ms.](/assets/images/lumma/rust/fig%206.png)


### The dropper

The dropper (`eed45ed3…`, x86) runs inside the hollowed MSBuild. Its work thread (`0x403910`) does three things.

**1. It decrypts two embedded programs from its `.cSs` section.** The routine at `0x401FE0` is RC4 with a **40-byte key**, and both embedded programs use the same key:

```text
c49890251bd0174e77071945f569c7702a2c764d70eaf91d0aa45044fcec13b5673c99e2c2fe5879
blob A @0x52B060 len 0x2C00  (11,264 B)   -> .NET clipper
blob B @0x431060 len 0xFA000 (1,024,000 B) -> second crypter
```

I confirmed both by decrypting them. Both blobs decrypt to valid PEs.

**2. It writes both programs to `%APPDATA%`.** It gets the AppData folder with `SHGetFolderPathA(CSIDL_APPDATA)`, and that API is also resolved by hash. The hashes match the same modified MurmurHash2, but with **seed 565** instead of 707. I matched them by hash only, and I didn't re-read the dropper's own hash function.

Each file gets a name of 10 random characters from `[0-9A-Za-z]`, followed by `.exe`. The name generator (`0x403740`) is a `std::mt19937` random-number generator seeded from `std::random_device`, so the names change on every run. My two runs show it:

| file | first run | second run |
|---|---|---|
| clipper | `%APPDATA%\4M7CkRYXzv.exe` | `%APPDATA%\lvwMBWUsH5.exe` |
| second crypter | `%APPDATA%\le4ybzlwTi.exe` | `%APPDATA%\qDKDZPMa5I.exe` |

In the first run, I matched the files to the clipper and the crypter by their hashes.

**3. It starts both files.** In both runs the hollowed MSBuild writes the two files and then becomes the parent of both new processes. The launch API is `ShellExecuteA` (hash `0x5E67C053`, seed 565) with the `"open"` verb. Like the crypter's hashes, it only resolves with the modified tail.

![Figure(7): The dropper decrypting its two embedded PEs with the same 40-byte RC4 key.](/assets/images/lumma/rust/fig%207.png)


![Figure(8): Procmon: one MSBuild process writes two random-named EXEs to %APPDATA% and starts both.](/assets/images/lumma/rust/fig%208.png)

### The crypto clipper

Drop A is an 11,264-byte .NET program.

**Where it comes from**

Its PDB path (the debug-symbol path the compiler leaves in the binary) is:

```text
C:\Users\alik777\Desktop\ShinobuClipper-master\Clipper\Clipper\obj\Debug\Runtime64.pdb
```

So the clipper was very likely built from a project folder named "ShinobuClipper-master". I have not identified the public repository behind that folder. `alik777` is just the user name on the machine that built it.

**How it disguises itself**

The version info claims CompanyName "Microsoft Windows", FileDescription "system32", ProductName "Windows System32 2024", Comments "Google inc" and OriginalFilename `Runtime64.exe`.

**What it does**

It's a small and simple clipper, and dnSpy decompiles it cleanly. Everything it does is driven by one `config` class:

```csharp
autorun_enabled       = true
autorun_name          = "svhost"
attribute_hidden      = false
attribute_system      = true
clipboard_check_delay = 1        
addresses             = { "btc": "1Cs4gSW7...", ... 13 entries ... }
mutex                 = "sodfksdkfalksdasgpkprgasdgrrkgwhrterheegwsdfwef"
```

`Main()` runs four steps:

1. **Mutex:** it creates the `sodfks…` mutex and exits if it already exists, so only one copy runs.
2. **Persistence:** if `Startup\svhost.exe` doesn't exist yet, it copies itself there.
3. **Attributes:** it sets file attributes on its own file.
4. **Clipboard loop:** it checks the clipboard once a second, forever.

The swap logic is short. If the clipboard text changed, the clipper tests it against 13 regular expressions, one per coin label (`btc, btc1, btc2, eth, xmr, xrp, trx, doge, btccash, ltc1, ltc2, ltc3, sol`). The first match wins, and the text is replaced with the attacker's address for that label. Two details matter here:

- **Whole-text matches only:** every pattern is anchored with `^…$`, so the clipper only swaps when the entire clipboard text matches. An address inside a sentence is left alone.
- **Some patterns are loose:** they check the shape of the text, not whether it's a real address. The loosest is `sol`, `^[a-zA-Z0-9]{44}$`, which matches any 44-character alphanumeric string. So the clipper can replace text that isn't an address at all.

To test it, I copied a known test BTC address in Notepad while the clipper was running. When I pasted, it had been replaced with the attacker's `btc` address `1Cs4gSW7qZiZnmUtYAJY6SNNL9RkGvqxk5`.

![Figure(9): The clipper's config class: wallets, autorun name, attribute flags and mutex.](/assets/images/lumma/rust/fig%209.png)

![Figure(10): Clipboard swap in the VM: the test BTC address becomes the attacker's address on paste.](/assets/images/lumma/rust/fig%2010.png)


**Persistence**

The Windows **Startup folder** runs everything in it when the user logs on ([T1547.001](https://attack.mitre.org/techniques/T1547/001/)). The clipper takes `Environment.SpecialFolder.Startup` and copies itself there as `svhost.exe`, which is a misspelling of the real `svchost.exe`. Both runs created `...\Start Menu\Programs\Startup\svhost.exe`. In the first run, a listing of the Startup folder showed it at 11,264 bytes, the same size as the clipper.

**Attributes**

This build turns the System attribute on and leaves Hidden off. The attribute code works on the file that is running, not on the Startup copy. That explains what I saw:

- After the second run, `attrib` on the dropped clipper (`lvwMBWUsH5.exe`) showed `A  S`: Archive plus System, and no Hidden.
- In the first run, the Startup copy had only Archive. It was copied but never run, so nothing set System on it. It will set System on itself the first time it runs at logon.

**Mutex**

The `sodfks…` string is the mutex name. When I checked the running clipper's handles in the first run, the mutex wasn't there. The code explains why: the `Mutex` object is a local variable that is never used again, so the .NET garbage collector can collect it and close the handle shortly after startup. This last part is my explanation from the code, and I didn't watch it happen.

The clipper has no registry code and no networking code. It works entirely offline and gets paid through the swapped addresses.

![Figure(11): Clipper persistence: the autorun code, and the svhost.exe copy being written to the Startup folder.](/assets/images/lumma/rust/fig%2011.png)


### The second crypter and Lumma Stealer

Drop B is the **same crypter build** as the outer EXE. It has:

- the same PE timestamp,
- the same `.text` size and section layout,
- two identical `.jss` sections (0x57800 bytes each),
- the same mobsync version info and broken security entry.

The same 10-byte RC4 key decrypts its `.jss`, so the key is a constant of the crypter build and not a per-payload key. The decrypted payload is a 358,400-byte 32-bit PE. VirusTotal detections identify it as **Lumma Stealer**.

In the first run, this second crypter lived for about 4 seconds. During that time it started one more 32-bit MSBuild, and that MSBuild produced all of the C2 traffic. So Lumma ran inside it, most likely through the same hollowing technique.

```text
AIO Checker 8.10.10.exe (x64 crypter)
 └─ MSBuild.exe (x86, hollowed)  = dropper
     ├─ %APPDATA%\<10 chars>.exe = .NET clipper  ──> Startup\svhost.exe
     └─ %APPDATA%\<10 chars>.exe = x64 crypter (same build)
         └─ MSBuild.exe (x86, hollowed) = Lumma Stealer ──> HTTPS C2
```

![Figure(12): Second run, Procmon process tree: the full chain from the lure EXE to the MSBuild that hosts Lumma.](/assets/images/lumma/rust/fig%2012.png)


### Lumma C2 configuration

Lumma's C2 list is encrypted with **ChaCha20**, a stream cipher. It turns a 32-byte key and a nonce into a keystream that is XORed with the data ([Bernstein](https://cr.yp.to/chacha.html)). This build uses the original variant with an 8-byte nonce and a 64-bit counter. The counter starts at 0, and one continuous keystream covers the whole table.

```text
key   (32 B) @0x450238: 51c67bc39ed47674a87aa1bcda254e392093463c3ea95ce616e45e2af746015d
nonce ( 8 B) @0x450258: e2afcfc4b7a71e71
table        @0x450260: 10 slots x 0x80 bytes
```

The decryption is set up at `0x40E187` and called at `0x40E393` and `0x40FDA3`. I confirmed it by decrypting the real table, and my extractor gives the same result.

| slot | entry (defanged) |
|---|---|
| 0 | empty (the code skips it, and I don't know what it is for) |
| 1 | exitiumt[.]digital/xane |
| 2 | brandihx[.]run/lowp |
| 3 | viriatoe[.]live/laopx |
| 4 | exitiumt[.]digital/xane (duplicate of slot 1) |
| 5 | opusculy[.]top/keaj |
| 6 | civitasu[.]run/werrp |
| 7 | scriptao[.]digital/vpep |
| 8 | praetori[.]live/vepr |
| 9 | disciplipna[.]top/eqwu |

The same function that decrypts slots 1–9 also builds a **Steam profile URL**, `hxxps://steamcommunity[.]com/profiles/76561199845513035`, and the string `actual_persona_name`. This is the pattern of a **dead-drop resolver** ([T1102.001](https://attack.mitre.org/techniques/T1102/001/)): the attacker writes the real C2 address as the profile's display name on a public site. I can see the strings in the code, but I did not see Lumma use them, so its role as a backup is **inferred**.

The plaintext build ID `37d7c3a0bc391b79b770bb89c2e2e1a3` is at `0x450AF5`.

![Figure(13): ChaCha20 key/nonce setup and the decrypted C2 table.](/assets/images/lumma/rust/fig%2013.png)


### Lumma C2 communication

Lumma tried **slot 1 first**. FakeNet answered it, and Lumma never tried slots 2–9 or the Steam profile, since there were no DNS queries for them. I don't know in what order it tries the other slots, or when it falls back to Steam.

All traffic was **HTTPS on TCP 443**, with the C2 host name in the TLS handshake (SNI). It consisted of three POST requests to `/xane`:

| # | request | body |
|---|---|---|
| 1 | check-in | `uid=37d7c3a0bc391b79b770bb89c2e2e1a3&cid=`, form-urlencoded, 41 bytes |
| 2 | upload | `multipart/form-data` with fields `uid`, `pid` = `1`, `hwid` (32 uppercase hex characters, redacted here) and `file` with `filename="data"` |
| 3 | final POST | `uid=<build id>&cid=&hwid=<hwid>` |

Some more details about these requests:

- The build ID is sent as **`uid`**, and `cid` is sent empty.
- The User-Agent is a fixed Chrome 109 on Windows 10 x64 string.
- The uploaded `file` was 1,536 bytes with entropy 7.89 and no ZIP or text header. It is likely encrypted or compressed, and I don't know its exact format.
- After the third request there were no more HTTP requests. In the first run, Sysmon logged two more DNS lookups for the C2 within the next 2 seconds, then nothing for the rest of the capture.

FakeNet doesn't behave like the real server, so I don't know what commands a live C2 can send back (for example download-and-execute).

**TLS:** Lumma accepted FakeNet's certificate. This is not because it skips certificate checks. FakeNet had installed its own root CA into the Windows trust store beforehand. What it shows is that Lumma trusts the system certificate store and does **not pin** its C2 certificate.

![Figure(14): The Lumma check-in captured by FakeNet-NG.](/assets/images/lumma/rust/fig%2014.png)


![Figure(15): The multipart upload request (hwid redacted).](/assets/images/lumma/rust/fig%2015.png)


### Lumma information stealing

Most of Lumma's strings are built on the stack one byte at a time and decoded inline. I decoded 67 of them with a small IDAPython emulator (not included in the repo), so my coverage is partial. The decoded strings and the code point to the following targets. I can see them in the code, but I could not see what the encrypted upload actually contained.

- **Browsers:**
  - Chromium-based: `Login Data`, `History`, `Web Data`, `leveldb`
  - Firefox: an IndexedDB (`idb`) path string (I inferred its purpose)
- **Crypto wallets:** a `Wallets/` folder name, likely a folder inside the uploaded archive.
- **Steam:** the registry key `SOFTWARE\Valve\Steam`.
- **Mail:** Windows Mail, and Outlook profiles (`Applications/Outlook/Profiles.txt`).
- **Notepad++ files** (`Important Files/Notepad++/`) and UWP app data (`\Packages`).
- **Host profile (`System.txt`):** OS version, install date, user, domain, computer name, language, elevation, CPU, cores, threads, RAM and GPU.
- **BIOS serial number:** a separate function (`0x4423E0`) queries WMI (`SELECT * FROM Win32_BIOS`). I couldn't tell where the result ends up.
- **Clipboard:** a clipboard-read function (`0x43D5C0`), which the check-in function calls.
- **Screenshot:** a GDI screen-capture sequence (`0x43DA00`–`0x43E2C0`) is in the code: `GetSystemMetrics` → `CreateCompatibleBitmap` → `BitBlt` → `GetDIBits`. IDA lost the function boundary there, so I only infer that it is actually reached.

To show what one of these looks like, I ran a single decode loop in x32dbg. The block at `0x422810` writes 18 encoded bytes into a buffer, and the loop at `0x422840` decodes them in place. After 18 rounds the buffer holds `Web Data` in UTF-16, which is the name of Chromium's autofill and saved-card database.

![Figure(16): One Lumma stack string decoded live: 18 encoded bytes on the stack (top) become "Web Data" (bottom).](/assets/images/lumma/rust/encoded.png) *encoded* |![fig](/assets/images/lumma/rust/decoded.png) *decoded*



### Anti-analysis

**Obfuscated strings:** Almost all strings are built on the stack and decoded byte by byte, so a plain `strings` run shows nothing useful.

**Anti-decompilation:** Hex-Rays fails on the main functions (`0x40D870`, `0x40DE30`, `0x410EF0`), so I worked from the disassembly.

**Hypervisor check (`0x4417C0`):**

- The CPUID instruction with leaf `0x40000000` returns a hypervisor vendor string inside a VM. I ran that one instruction in x32dbg in my VMware VM, and EBX, ECX and EDX came back as `VMwa`, `reVM` and `ware`.
- Lumma keeps the ECX part and compares it with five values: `VMKV` (KVM), `CGTC` (QEMU-TCG), `reVM` (VMware), `VBox` (VirtualBox) and `MMXe` (Xen). Each value is decoded on the stack right before its compare (`0x441985`, `0x441ACC`, `0x441BE1`, `0x441C6A`, `0x441CBC`). I decoded the first one by hand. The other four come from a decoding script (not included in the repo) that I checked against two hand-decoded values.
- The check only runs when a runtime flag is set (`0x4122E6`), and I don't know what Lumma does when it matches.
- Lumma still talked to its C2 in my VMware VM, so either the flag was off or a match does not stop it.

**Direct syscalls (likely):** There is a `mov edx,esp; sysenter; ret` stub (`0x449666`), and the binary also contains native API strings such as `NtFreeVirtualMemory` and `\??\` paths. This points to calling the kernel directly to avoid user-mode API hooks. I tag this as inferred.

**Outer crypter under a debugger:** It exits with code 0 before starting its loader thread when run under x64dbg with ScyllaHide, even with no breakpoints. I searched the whole binary for anti-debug code and found none: no reads of the PEB `BeingDebugged` or `NtGlobalFlag` fields, no `rdtsc` timing, no `int 2Dh`, and `IsDebuggerPresent` only in the C runtime's error paths. So whatever makes it exit under the debugger isn't a debugger check in this code, and I don't know what it is.



---

## Conclusion

AIO Checker is a lure tool wrapped around a layered delivery chain:

- a reused x64 crypter that clones Microsoft metadata,
- a dropper that hides in MSBuild,
- an offline clipper that stays on the machine through the Startup folder, and
- Lumma Stealer, which in my first run uploaded one opaque blob over HTTPS and then went quiet.

None of the individual techniques are new. What makes the chain effective is that it combines them. The crypter's static imports and metadata look harmless, the dropper and Lumma run inside a genuine Microsoft binary (MSBuild), and the victim ends up with both a data theft and a long-lived wallet hijacker.

Here are a few good places for defenders to look:

- the 32-bit .NET Framework `MSBuild.exe` started with no arguments by a non-developer parent,
- MSBuild writing and launching EXEs in `%APPDATA%`,
- MSBuild making outbound HTTPS connections,
- a `svhost.exe` in the user's Startup folder.


## MITRE ATT&CK


| tactic | technique | where | basis |
|---|---|---|---|
| Execution | T1204.002 User Execution: Malicious File | the victim runs `AIO Checker 8.10.10.exe` | inferred |
| Persistence | T1547.001 Registry Run Keys / Startup Folder | clipper copies itself to `Startup\svhost.exe` | seen |
| Defense Evasion | T1055.012 Process Hollowing | both crypters → 32-bit MSBuild | code (full API sequence), MSBuild launches seen |
| Defense Evasion | T1036.005 Match Legitimate Name or Location | `svhost.exe` in Startup | seen |
| Defense Evasion | T1036 Masquerading | crypter: version info cloned from `mobsync.exe` | code (PE metadata) |
| Defense Evasion | T1027.007 Dynamic API Resolution | modified MurmurHash2, seeds 707 / 565 | code (all hashes resolved) |
| Defense Evasion | T1027 Obfuscated Files or Information | RC4-encrypted stages, control-flow flattening, stack strings | code |
| Defense Evasion | T1140 Deobfuscate/Decode Files or Information | RC4 (crypter, dropper), ChaCha20 (C2 list) | code; decryption reproduced in Python |
| Defense Evasion | T1497.001 System Checks | Lumma CPUID hypervisor-vendor check | code (gated by a runtime flag; effect unknown) |
| Collection | T1115 Clipboard Data | clipper (read and replace); Lumma clipboard read | seen (clipper); code (Lumma) |
| Collection | T1113 Screen Capture | Lumma GDI capture code | code; reachability inferred |
| Credential Access | T1555.003 Credentials from Web Browsers | Lumma `Login Data`, `Web Data` | code (decoded strings) |
| Discovery | T1082 System Information Discovery | Lumma `System.txt`, WMI `Win32_BIOS` | code |
| Command and Control | T1071.001 Web Protocols | HTTPS POST to `/xane` | seen |
| Command and Control | T1102.001 Dead Drop Resolver | Steam profile URL next to the C2 list | code; use inferred |
| Exfiltration | T1041 Exfiltration Over C2 Channel | multipart upload of `data` | seen |

## IoCs

```text
No. | Type          | Description                                   | Value
----+---------------+-----------------------------------------------+------------------------------------------------------------------
 1  | sha256        | Lure archive AIO Checker 8.10.10.rar          | 8f5e4c1fffb23cf75e702fd241f3ae5937ac5cdc495ce1b50659b2b1305b89ff
 2  | sha256        | Outer crypter AIO Checker 8.10.10.exe (x64)   | 70ed41327068060f68a7272cc705ba1eecfa11430e308023eb82d7964f42ed1d
 3  | md5           | Outer crypter                                 | 75aee7f868d71cc6f8029aef153092d2
 4  | sha256        | Dropper (x86, decrypted from .jss)            | eed45ed3b3f866d87a00cbebfbf500ee3da5b0285097ea726ec896968f0e1203
 5  | sha256        | .NET crypto clipper (Runtime64.exe)           | ed6731c5d5de872e56816984faf9bb056e4d3e3282862f2f626d2df75b38d6da
 6  | sha256        | Second crypter (same build as #2)             | 1321e9fa6893b6fd3137f01b77b54eee6bd39144813d06e6f92bf8c58f3a3008
 7  | sha256        | Lumma Stealer (x86, decrypted)                | 7584e49b7ad4e44f405dc64a391abe2f619253b2396d357b9ed7c4ffc867ada9
 8  | sha256        | README.txt in archive                         | 8df26b1f550c80646f01d25b8aafcabb1342bbb2be1cd335cdb8d254be8c4090
 9  | domain        | Lumma C2 (slot 1/4, contacted in run)         | exitiumt[.]digital
10  | url           | Lumma C2 endpoint (observed)                  | hxxps://exitiumt[.]digital/xane
11  | domain        | Lumma C2 (slot 2, /lowp)                      | brandihx[.]run
12  | domain        | Lumma C2 (slot 3, /laopx)                     | viriatoe[.]live
13  | domain        | Lumma C2 (slot 5, /keaj)                      | opusculy[.]top
14  | domain        | Lumma C2 (slot 6, /werrp)                     | civitasu[.]run
15  | domain        | Lumma C2 (slot 7, /vpep)                      | scriptao[.]digital
16  | domain        | Lumma C2 (slot 8, /vepr)                      | praetori[.]live
17  | domain        | Lumma C2 (slot 9, /eqwu)                      | disciplipna[.]top
18  | url           | Steam dead-drop profile (role inferred)       | hxxps://steamcommunity[.]com/profiles/76561199845513035
19  | build-id      | Lumma uid                                     | 37d7c3a0bc391b79b770bb89c2e2e1a3
20  | url           | Telegram link in README                       | hxxps://t[.]me/hitbase
21  | file path     | Clipper persistence                           | %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\svhost.exe
22  | file pattern  | Dropper output (random names)                 | %APPDATA%\[0-9A-Za-z]{10}.exe
23  | process       | Hollowing target (both crypters)              | C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe (no args)
24  | user-agent    | Lumma HTTP UA (common, low value alone)       | Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36
25  | wallet        | Clipper replacement address (btc)             | 1Cs4gSW7qZiZnmUtYAJY6SNNL9RkGvqxk5
26  | wallet        | Clipper replacement address (btc1)            | 36XmjPBaivX7XNDcPFUkgdEVpuxVMgsd9w
27  | wallet        | Clipper replacement address (btc2)            | bc1qnfer7radees05zrns2vqtw7ykmjxluldewtd7w
28  | wallet        | Clipper replacement address (eth)             | 0x01bA6297Bb9a7E1d02409fa266B6cc0394eBB46d
29  | wallet        | Clipper replacement address (xmr)             | 4Af2kkWQNCDEFyk7nxNtGFZ3nNgrfzEZVaVJPxQ5VJ42X9c2Lpzne2QJ1ViCe5vdBK8mMUJa6XS5zKNSUoHM6rz6Bk3zNJQ
30  | wallet        | Clipper replacement address (xrp)             | rQBgyfhUiZ1rjD5L5r2pMngpDGTYd3ZKYE
31  | wallet        | Clipper replacement address (trx)             | TXFaM1RxKK71QL4cpXLtQu4w2ZkzhJHVwk
32  | wallet        | Clipper replacement address (doge)            | DCU6eByBxk81oykGdQbS51qXHyj8qLdGkA
33  | wallet        | Clipper replacement address (btccash)         | qpppd8hu5epj600jmsdr0sn4tl687whjk50ptgwsch
34  | wallet        | Clipper replacement address (ltc1)            | MGx8Gz8ovhDQg3hqqBwcC83KGh79sNiNzb
35  | wallet        | Clipper replacement address (ltc2)            | LTRjZtwiSXr6ur88BCo8qBXaEnkscwsu5N
36  | wallet        | Clipper replacement address (ltc3)            | ltc1q85llmq9ad7kczk7unyzt2tv4jmeztn2mcsfeqw
37  | wallet        | Clipper replacement address (sol)             | upQCkfeHcnPUCe2LLZH1diiupjEBSvHkghG8Q4Ls6h8
```

I left the two DLLs in the archive (`dnscmmc.dll` 4f64dc86…, `elshyph.dll` 36732268…) out on purpose. They look like genuine Windows files, and listing them could cause false positives.

## YARA Rules

```yara
import "pe"

rule AIOChecker_Crypter_x64_jss
{
    meta:
        description = "x64 crypter from the AIO Checker chain: two .jss sections, mobsync.exe version info clone, RC4 key built as stack immediate"
        author      = "Artful Dodger"
        date        = "2026-10-11"
        status      = "TESTED"
        hash1       = "70ed41327068060f68a7272cc705ba1eecfa11430e308023eb82d7964f42ed1d"
        hash2       = "1321e9fa6893b6fd3137f01b77b54eee6bd39144813d06e6f92bf8c58f3a3008"

    strings:
        // low 8 bytes of the 10-byte RC4 key, as the imm64 of the stack build at 0x14000D6E7
        $rc4_key_imm = { 92 54 67 56 42 11 36 4D }

    condition:
        uint16(0) == 0x5A4D and
        pe.machine == pe.MACHINE_AMD64 and
        for 2 i in (0 .. pe.number_of_sections - 1) : ( pe.sections[i].name == ".jss" ) and
        (
            $rc4_key_imm or
            (
                pe.version_info["OriginalFilename"] == "mobsync.exe" and
                pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_SECURITY].size == 0x2628 and
                pe.number_of_signatures == 0
            )
        )
}

rule AIOChecker_ShinobuClipper_variant
{
    meta:
        description = ".NET crypto clipper built from a 'ShinobuClipper-master' project (Runtime64.exe, Startup\\svhost.exe)"
        author      = "Artful Dodger"
        date        = "2026-10-11"
        status      = "TESTED"
        hash1       = "ed6731c5d5de872e56816984faf9bb056e4d3e3282862f2f626d2df75b38d6da"

    strings:
        $pdb    = "ShinobuClipper-master" ascii
        $pdb2   = "Runtime64.pdb" ascii
        $m1     = "attribute_hidden" ascii
        $m2     = "attribute_system" ascii
        $m3     = "autorun_name" ascii
        $m4     = "startup_directory" ascii
        $odd    = "sodfksdkfalksdasgpkprgasdgrrkgwhrterheegwsdfwef" ascii wide
        $wallet = "1Cs4gSW7qZiZnmUtYAJY6SNNL9RkGvqxk5" wide

    condition:
        uint16(0) == 0x5A4D and filesize < 200KB and
        // .NET check via the CLR (COM descriptor) directory; avoids the 1-argument pe.imports() form
        pe.data_directories[pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].virtual_address != 0 and
        ( $pdb or $odd or $wallet or ($pdb2 and 2 of ($m*)) or all of ($m*) )
}

rule AIOChecker_Lumma_build_37d7c3a0
{
    meta:
        description = "Lumma Stealer payload from the AIO Checker chain (this build only): plaintext uid and ChaCha20 key+nonce of the C2 table"
        author      = "Artful Dodger"
        date        = "2026-10-11"
        status      = "TESTED"
        hash1       = "7584e49b7ad4e44f405dc64a391abe2f619253b2396d357b9ed7c4ffc867ada9"

    strings:
        $uid       = "37d7c3a0bc391b79b770bb89c2e2e1a3" ascii
        // key @0x450238 (32 B) immediately followed by nonce @0x450258 (8 B)
        $key_nonce = { 51 C6 7B C3 9E D4 76 74 A8 7A A1 BC DA 25 4E 39
                       20 93 46 3C 3E A9 5C E6 16 E4 5E 2A F7 46 01 5D
                       E2 AF CF C4 B7 A7 1E 71 }

    condition:
        uint16(0) == 0x5A4D and filesize < 2MB and
        ( $uid or $key_nonce )
}
```

## References

- Virus Total `https://www.virustotal.com/gui/file/70ed41327068060f68a7272cc705ba1eecfa11430e308023eb82d7964f42ed1d`
- MITRE ATT&CK T1055.012, Process Injection: Process Hollowing — https://attack.mitre.org/techniques/T1055/012/
- MITRE ATT&CK T1547.001, Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder — https://attack.mitre.org/techniques/T1547/001/
- MITRE ATT&CK T1102.001, Web Service: Dead Drop Resolver — https://attack.mitre.org/techniques/T1102/001/
