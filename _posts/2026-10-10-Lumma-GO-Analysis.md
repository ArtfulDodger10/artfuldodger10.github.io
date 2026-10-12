---
title: "Lumma Campaign GO Loader"
date: 2026-10-10 00:00:00 +0300
description: "Reversing a Go loader that hides Lumma Stealer inside itself and injects it into explorer.exe."
tags:  
- lumma
- lummac2
- infostealer
- golang
- go
- process hollowing
- chacha20
- api hashing
- config extraction
- YARA
- Malware Analysis
- Reverse Engineering
- Blue Team
categories: [Malware Analysis]
image: /assets/images/lumma/Blog banner.png
---


**On this page**
- [Lumma TL;DR](#lumma-TL;DR)
- [Infection Vector](#infection-vector)
- [Technical Summary](#technical-summary)
- [Technical Analysis](#technical-analysis)
  - [Stage 1: First look at the Go loader](#stage-1-first-look-at-the-go-loader)
  - [Unpacking the embedded payload (static)](#unpacking-the-embedded-payload-static)
  - [Dropping the payload with x64dbg (dynamic)](#dropping-the-payload-with-x64dbg-dynamic)
  - [Process Hollowing into explorer.exe](#process-hollowing-into-explorerexe)
  - [Stage 2: First look at the stealer](#stage-2-first-look-at-the-stealer)
  - [String Obfuscation](#string-obfuscation)
  - [API Hashing](#api-hashing)
  - [Configuration Extraction](#configuration-extraction)
  - [C2 Communication](#c2-communication)
  - [Anti-Analysis](#anti-analysis)
  - [Host Profiling](#host-profiling)
  - [Information Stealing](#information-stealing)
  - [Remote Execution](#remote-execution)
  - [Persistence and Cleanup](#persistence-and-cleanup)
  - [What capa saw (and missed)](#what-capa-saw-and-missed)
- [Conclusion](#conclusion)
- [IoCs](#iocs)
- [MITRE ATT&CK](#mitre-attck)
- [YARA Rule](#yara-rule)
- [How this analysis was done](#how-this-analysis-was-done)
- [References](#references)

## Lumma TL;DR

This post covers a two-stage chain I'll call the **"GO campaign"**: a loader written in **Go** that carries an infostealer inside itself, decodes it in memory, and injects it into a 32-bit copy of `explorer.exe`. The injected payload is an infostealer. Its code and behaviour (a ChaCha20-encrypted C2 list, a Steam-profile dead drop, the `uid`/`hwid`/`pid` request fields, the `__cf_mw_byp` cookie and per-string obfuscation) match the infostealer family known as **Lumma Stealer**, so I assess the payload is probably Lumma. That rests on how the code looks, not yet on an outside source.


![Figure(0)](/assets/images/lumma/stage1 VT.png) | ![Figure(0)](/assets/images/lumma/stage2%20VT.png)


Throughout this post, "stage 2" and "the stealer" refer to this payload.

An infostealer is malware built to collect valuable data from an infected machine (saved passwords, browser cookies, crypto wallets, messenger tokens, email data) and send it to the attacker. This sample very likely also has a **loader** role: its code can download and run further payloads when its C2 asks it to.

## Infection Vector

Not determined from the samples. 

## Technical Summary

- <ins>**Stage 1 (Go Loader):**</ins> A 64-bit Go binary padded with junk code. It carries the Lumma payload inside its own data and decodes it in memory with a simple reverse-and-shift routine. This is encoding, not encryption.

- <ins>**Process Hollowing:**</ins> The loader starts a 32-bit `explorer.exe` suspended, writes the payload into it, points the thread at the payload's entry point and resumes it.

- <ins>**Stage 2 (Lumma Stealer):**</ins> A 32-bit binary with almost no imports. Every string is hidden behind its own small decoder, and Windows APIs are resolved at run time by hash.

- <ins>**Configuration:**</ins> A campaign ID and 9 C2 servers encrypted with ChaCha20. If all of them fail, it falls back to a Steam profile and reads the C2 from the profile name.

- <ins>**C2 Communication:**</ins> HTTPS POST requests with a Chrome User-Agent. It sends the stolen data in one request and a check-in with the campaign and machine IDs in another.

- <ins>**Anti-Analysis:**</ins> Exits if the system language is Russian. It also checks whether it's running under a hypervisor, but that check didn't stop it in a VM.

- <ins>**Information Stealing:**</ins> Targets browser data, crypto wallets, email clients, Steam, Discord and Notepad++, and collects a full system profile.

- <ins>**Remote Execution:**</ins> The code contains the paths and command lines for dropping `.exe`, `.dll` and `.ps1` payloads into `%TEMP%` and running them with `rundll32` or PowerShell. This wasn't seen running in the lab.


![Figure(1)](/assets/images/lumma/GO%20chain.png)
*infection chain*

## Technical Analysis

### Stage 1: The Go loader


The first thing worth noting is that the Go symbols are **not stripped**. The function names in the binary are honest about what it does: `main.LoadFile`, `main.Decode`, `main._LoadPEModule`, `main._RunPE`, `main.RedirectToPayload`, `main.Wow64Set_ThreadContext`. The author relied on **junk code** instead. Every `main.*` function carries a large closure full of floating-point maths, map operations and comparisons against words like "temperature", "pressure" and "maintenance". It's almost certainly filler: none of its results reach the decode or the injection calls, and it only makes the decompiler output long.

![Figure(2)](/assets/images/lumma/main.png) *main*| ![Figure(2)](/assets/images/lumma/decode.png) *main.decode* | ![Figure(2)](/assets/images/lumma/loadfile.png) *main.LoadFile*| ![Figure(2)](/assets/images/lumma/RunPE.png) *main.RunPE*


![Figure(3)](/assets/images/lumma/decode%20loop.png) *decode loop at top* | ![Figure(2)](/assets/images/lumma/junk.png) *junk code at bottom*


Reading `main.main` in order gives the whole plan of the loader:

`LoadFile → _LoadPEModule → Decode (target path) → CreateProcess → Virtual_AllocEx → _RunPE`

The Windows APIs used for injection (`WriteProcessMemory`, `ResumeThread`, `Wow64GetThreadContext`, `Wow64SetThreadContext`, `VirtualAlloc`, `VirtualAllocEx`) are **not imported**. Go's `syscall.LazyProc` resolves them at run time from plain-text names stored in the data section. Keep this in mind: it's why import-based tools miss the injection (see [What capa saw](#what-capa-saw-and-missed)).

### Unpacking the embedded payload (static)

The payload is embedded, not downloaded. `main.LoadFile` builds a **0x51A08-byte (334,344-byte)** blob on the stack: an 8-byte immediate (`0x9013AA0199048FFF`) followed by a `rep movsq` of 0xA340 qwords from the read-only data section (VA `0x140183688`, file offset `0x182688`).

![Figure(4)](/assets/images/lumma/build%20blob.png)
*The blob is assembled from one immediate plus a block copy from `.rdata`*

The decode runs in two passes:
1. **Reverse** the whole buffer, last byte first.
2. Walk the reversed buffer: **subtract 0x43** from bytes at even positions and **add 0x43** to bytes at odd positions (mod 256).

The same routine (`main.Decode`) also decodes a 35-byte stack string just before `CreateProcess`. That string gives the injection target, `C:\\Windows\\SysWOW64\\explorer.exe` (the doubled backslashes are in the sample, and Windows accepts them). This small string was how I proved the algorithm before running it on the big blob.

![Figure(5)](/assets/images/lumma/decode%20loop.png)

The decoded result is a complete 32-bit PE, **stage 2**, SHA256 `7c9d4d29…46df`. Before injection, the loader stages the decoded bytes in a pagefile-backed section (`CreateFileMapping(INVALID_HANDLE_VALUE, PAGE_READWRITE, 0x51A08)`), copies them into a `VirtualAlloc` buffer, and unmaps the view.

Because the blob boundaries come straight from the code (the 8-byte immediate and the `rep movsq` count), unpacking needs no debugger. I wrote a small static unpacker, `go_loader.py`. It finds the blob-builder instructions by pattern, resolves the RIP-relative address of the blob, and applies the decode. It produces the exact stage 2 file and should work on other builds of the same loader.

![Figure(2)](/assets/images/lumma/unpack%20s1.png)

### Dropping the payload with x64dbg (dynamic)

To cross-check the static result, I also dropped stage 2 from a debugger . The loader had been relocated by ASLR, so every IDA address is shifted. Two breakpoints were enough:

| # | IDA address | Where | What you get |
|---|---|---|---|
| 1 | `0x1400a0c3e` | first instruction after the decode loop in `main.LoadFile` | `rbx` = decoded PE (starts with `MZ`), size 0x51A08 |
| 2 | `0x14007a317` | `CreateProcessW` call | the hollowing is about to start; stop here and never resume the child |

At breakpoint 1, a single x64dbg command dumps the payload:

```text
savedata "<dump folder>\stage2_dbg.bin", rbx, 0x51A08
```

![Figure(6)](/assets/images/lumma/MZ%20there.png)
*Breakpoint 1: the decoded payload in memory begins with `MZ`*

![Figure(7)](/assets/images/lumma/holllowing.png)
*Breakpoint 2: `CreateProcessW` for the 32-bit explorer, created suspended*

The dumped file is byte-for-byte identical to the static unpacker's output (same SHA256, `7c9d4d29…46df`), so the two methods confirm each other.

### Process Hollowing into explorer.exe

Process hollowing means starting a legitimate process in a suspended state, replacing what it will run with malicious code, then letting it continue. From the outside, it looks like a normal `explorer.exe`.

The loader does it in five steps:

1. **Lay out the PE as it will look in memory** (`main._LoadPEModule`). On disk, sections are packed by file alignment; in memory, each section sits at its virtual address. `SectionsRawToVirtual` builds the in-memory layout locally (SizeOfImage bytes), doing the Windows loader's job by hand.
2. **Create the host** with `CreateProcessW(NULL, "C:\\Windows\\SysWOW64\\explorer.exe", …, CREATE_SUSPENDED, …)`. It picks SysWOW64 because stage 2 is 32-bit and the host has to match the payload's architecture.
3. **Allocate and write.** It calls `VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)`, where the size is probably the payload's SizeOfImage, applies relocations for the new base (`RelocateModule`), then writes the image with `WriteProcessMemory`.
4. **Redirect** (`main.RedirectToPayload`). It writes the new image base into the remote PEB (offset 8 for a 32-bit PEB, 0x10 for 64-bit) and sets the thread's entry point with `Wow64GetThreadContext` / `Wow64SetThreadContext`. Given that both the payload and the host are 32-bit, the WOW64 branch is almost certainly the one used; I didn't step through it.
5. **Resume** with `ResumeThread`. Stage 2 now runs inside `explorer.exe`, and the loader exits about a second later.

```text
main.main
  0x14007a317  call syscall.CreateProcess      ; SysWOW64\explorer.exe, CREATE_SUSPENDED
  0x14007a338  call main.Virtual_AllocEx       ; RWX region in the new process
  0x14007ad22  call main._RunPE

main._RunPE
  0x1400b25b3  call main.RelocateModule        ; fix addresses for the new base
  0x1400b3948  call main.Write_ProcessMemory   ; write stage 2 into explorer.exe
  0x1400b396d  call main.RedirectToPayload     ; PEB image base + thread entry point
  0x1400b430a  call LazyProc.Call              ; ResumeThread

main.RedirectToPayload
  0x1400b0a00  call main.GetRemotePebAddr
  0x1400b1380  call main.GetImgBasePebOffset   ; 8 for 32-bit PEB, 0x10 for 64-bit
  0x1400b09e0  call main.UpdateRemoteEntryPoint ; Wow64Get/SetThreadContext
```

Two details matter for memory forensics. The loader contains no `VirtualProtect*` or `NtUnmapViewOfSection` strings, so it very likely leaves the payload in **one private RWX region** and **doesn't unmap the original explorer image**. (Stage 2 could still change that region's protection later; I didn't check.) The payload therefore lives in a **separate** region alongside a normal-looking explorer image. A SysWOW64 `explorer.exe` holding a private, executable, writable region that contains a PE image is a strong hunting lead.

![Figure(9)](/assets/images/lumma/fig%209.png)
*At run time, the loader creates the 32-bit explorer and exits about 1.3 seconds later*

### Stage 2:  The stealer

Stage 2 shows almost nothing at first glance. The import table only has GDI32 (very likely for screen capture), clipboard functions, COM/WMI, SHELL32's `SHGetFileInfoW` and a few kernel32 calls, and IDA finds only 74 strings in the whole binary. Everything interesting is hidden behind three layers: string obfuscation, API hashing, and an encrypted configuration.

![Figure(10)](/assets/images/lumma/imports.png)
*Stage 2's tiny import table.*

### String Obfuscation

Strings are never stored in clear. Each string is built on the stack from `mov [esp+X], imm` instructions and passed to its **own** small decoder function, about 337 decoders for 682 call sites. Every decoder is a loop of the form `for (i = 0; i < N; i++) b[i] = MBA(b[i], i ^ k)`. MBA (mixed boolean-arithmetic) is a way of rewriting simple operations as long, confusing combinations of `+`, `&`, `|`, `^` and `~`, so each decoder looks different even though they all do the same kind of thing. Even the loop counters are written this way: `((i + 0x0AD5DEB1) | 0xF52A2150) + ((i + 0x0AD5DEB1) & 0xF52A2150)` is just `i + 1`.

![Figure(11)](/assets/images/lumma/a%20decoder%20dunc.png)
*One of the ~337 per-string decoders. The loop counter itself is obfuscated*

Rather than simplify each expression by hand, I let IDAPython read the Hex-Rays output of every decoder, translate the expression to Python, rebuild the input bytes from the stack writes before each call, and evaluate it. This recovered **497 of 682** strings, for example `uid=`, `&hwid=`, `POST`, the full User-Agent and `Build Date: Nov 26 2025`. Most of the rest are obfuscated 4-byte constants rather than text.

### API Hashing

Stage 2 resolves its Windows APIs at run time. Its resolver walks a DLL's export table and compares each name's hash with the one it wants. The hash is **FNV-1a (32-bit)** with a **non-standard offset basis, `0x69BBE5D1`** (the standard one is `0x811C9DC5`) and the standard prime `0x01000193`. Both constants are themselves hidden as obfuscated stack values.

```python
def fnv1a(name: bytes) -> int:
    h = 0x69BBE5D1
    for c in name:
        h = ((h ^ c) * 0x01000193) & 0xFFFFFFFF
    return h

hex(fnv1a(b"WinHttpSetTimeouts"))   # 0xcf43bdcf, pushed at 0x40e37e
```

Hashing the export names of the system DLLs and matching them against the pushed constants resolved **43 API names**. Among them are the full WinHTTP set, `CryptUnprotectData`, the `NCrypt*` functions, `CreateDesktopW` / `OpenDesktopW` and `GetUserDefaultUILanguage`.

![Figure(12)](/assets/images/lumma/http%201.png) | ![Figure(12)](/assets/images/lumma/http%202.png)

*The WinHTTP functions resolved by hash, annotated in IDA*

### Configuration Extraction

The C2 list is stored **encrypted with ChaCha20** (the original 64-bit-nonce variant). Even the cipher's `expand 32-byte k` constant is hidden as an obfuscated stack string.

| Item | Value |
|---|---|
| Key (32 bytes) @ `0x44B238` | `972ce069e3b6756f6de83a46dd2cbb35a0a4d4d5280966145020d6924e31e1da` |
| Nonce (8 bytes) @ `0x44B258` | `cd1fbfdb5c98bb36` |
| C2 table @ `0x44B2E0` | 9 entries × 128 bytes |
| uid @ `0x44BAB1` (plain text) | `dc8e5f3081889c0e241b9a0281076771effc3817c5b1cd4ddb43b54f` |
| Second config string (almost certainly `cid`) | empty string in this build |

There is one trap here. The cipher **writes its block counter back** into its context after every call, so the keystream continues from one decryption to the next instead of restarting at zero. Decrypting each entry with counter 0 gives garbage. In this build, slot *i* decrypts with counter **2 + 2·i**. Each 128-byte entry uses two 64-byte blocks, and almost certainly another 128-byte entry is decrypted first, taking blocks 0 and 1.

![Figure(13)](/assets/images/lumma/chacha.png)
*The ChaCha20 context is set up from the key and nonce stored in the binary*

![Figure(14)](/assets/images/lumma/fig14.png)
*The counter is saved back to the context, so the keystream runs on across calls*

The second configuration string sits right next to the uid pointer and is empty in this build. It is almost certainly the `cid` value: the captured check-in (see below) sends an empty `cid=`, and the code reads this string right between building `&hwid=` and `&cid=`. My extractor calls it `tag` because I named the field before the traffic confirmed it.

`lumma_config.py` finds the key, nonce and table by code pattern (no fixed offsets) and outputs the configuration as JSON. The Steam dead-drop URL is a stack string, which the stand-alone extractor doesn't decode: it prints that URL only for this reference sample (matched by hash), and other builds need the IDA string helper.

![Figure(14)](/assets/images/lumma/config%20ex.png)
*Config Extraction*




### C2 Communication

**Failover.** The slot index is kept as `byte ^ 0xF6`. Slots 0–8 are the encrypted C2 list, tried in order (almost certainly; I didn't trace the increment). Index 9 switches to the **Steam dead drop**. The sample fetches `hxxps://steamcommunity[.]com/profiles/76561199880317058`, takes the text after `<span class="actual_persona_name">` (the profile's display name), and shifts its lowercase letters by **ROT15** to get a working C2 host. Using a public service like Steam lets the operator change the C2 without rebuilding the malware.


| Slot | C2 |
|---|---|
| 0 | `convuey[.]cyou` |
| 1 | `bendavo[.]su/asdsa` |
| 2 | `conxmsw[.]su/vcsf` |
| 3 | `narroxp[.]su/rewd` |
| 4 | `squeaue[.]su/qwe` |
| 5 | `ozonelf[.]su/asd` |
| 6 | `exposqw[.]su/casc` |
| 7 | `squatje[.]su/asdasd` |
| 8 | `vicareu[.]su/bcdf` |
| fallback | Steam profile `76561199880317058`, ROT15 display name |

**Protocol.** All traffic goes over **HTTPS through WinHTTP** (the code sets port 443), as `POST` requests with the User-Agent `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.120 Safari/537.36`. With FakeNet answering in the lab, I captured two requests to slot 0:

![Figure(15)](/assets/images/lumma/fig%2015.png)
*multipart form with `uid`, `pid=1`, `hwid` and an encrypted `file` named `data`*

![Figure(16)](/assets/images/lumma/fig%2016.png)
*The check-in: `uid=<uid>&cid=&hwid=<hwid>`*


The `hwid` is probably built from BIOS information (WMI `Win32_BIOS`) and disk volume information, which are read in the same routine. The code also contains a `Cookie: __cf_mw_byp=` header, which wasn't sent in these requests, and the string `{"typ":"JWT","alg":"EdDSA"}`. That second string suggests the C2's replies (the task list) are **signed with Ed25519**, which would stop a fake server from driving the stealer. It fits what I saw: after FakeNet's reply, the sample sent nothing more and exited.

### Anti-Analysis

**Geofencing.** Right at the start, the sample calls `GetUserDefaultUILanguage` (resolved by hash `0x8CED6615`) and compares the result with **0x0419 (Russian)**. On a match, it exits (`ExitProcess(0)`), most likely after showing the decrypted message *"This country is not supported!"*.

![Figure(17)](/assets/images/lumma/russian%201.png)|![Figure(17)](/assets/images/lumma/russia%20not%20supported.png)|![Figure(17)](/assets/images/lumma/warning.png)
*The Russian-language check*

**Hypervisor check.** It reads the CPUID hypervisor leaf (`0x40000000`) and compares the vendor string against `VMKV` (KVM), `CGTC` (QEMU TCG), `reVM` (VMware), `VBox` (VirtualBox) and `MMXe` (Xen). In my VMware VM, this check did **not** stop it from contacting the C2 and uploading data. What it does with the result is hidden behind control-flow flattening and wasn't determined.

**Obfuscation.** Besides the string and API protection, the code uses control-flow flattening (indirect jumps through tables) and contains a **Heaven's Gate** stub: a far jump into 64-bit mode from a 32-bit process, a known way to make direct 64-bit system calls.

### Host Profiling

Stage 2 builds a system report named `Info.txt` from decrypted labels:
- the build date and execution path;
- processor, cores and threads, installed RAM;
- GPU (WMI `Win32_VideoController`), display resolution;
- user language, time zone, computer and user name, elevation;
- BIOS (WMI);
- installed antivirus (WMI `root\SecurityCenter2`).

It also lists installed software from the `Uninstall` registry keys (`Software.txt`) and running processes (`Processes.txt`). Its GDI32 imports (`BitBlt`, `CreateDIBSection`) and clipboard imports most likely serve screen capture and clipboard theft.

### Information Stealing

**What the code references** (from the decrypted strings):
- **Chromium browsers:** `Local State`, `History`, extension storage (`Local Extension Settings`, `IndexedDB\chrome-extension_`), and Chrome's newer **app-bound encryption**: `app_bound_encrypted_key`, `v20`, and the NCrypt "Microsoft Software Key Storage Provider". The same area creates a **hidden desktop** (`CreateDesktopW` with the name `ChromeBuildTools`), probably to run Chrome out of sight while it decrypts those keys.
- **Firefox:** `logins.json`, `cookies.sqlite`, `cert9.db`, `formhistory.sqlite`, `places.sqlite`, `prefs.js`, and extension storage.
- **Wallets:** `Wallets/` plus browser-extension storage.
- **Email:** Outlook profiles (`Applications/Outlook/Profiles.txt`), Windows Mail `*.eml`, Thunderbird.
- **Apps:** Steam (`config.vdf`, `Tokens.txt`), Discord / DiscordPTB tokens (its routine also reads `encrypted_key` from `Local State`).

**What it actually touched at run time**, without real C2 tasking (Procmon, `CreateFile` events):
- Windows Mail (`…\microsoft.windowscommunicationsapps_8wekyb3d8bbwe\LocalState\Indexed\LiveComm\`)
- `%APPDATA%\Thunderbird\Profiles`
- `%APPDATA%\Notepad++\session.xml`. This target doesn't appear in the strings I recovered; its string is probably among the ones my helper couldn't decode.
- `%APPDATA%\Discord\Local State`, `DiscordCanary\Local State`, `DiscordPTB\Local State`

![Figure(18)](/assets/images/lumma/fig%2018.png)

The built-in targets probed within about one second.

Notably, it touched **no browser profile and no wallet path** in either run. A likely explanation, though not the only one, is that browser and wallet targets come from the C2's signed task list, while the built-in set above runs without it. If that's right, the browser theft can't be observed with a fake C2, and the code is the evidence for it.

**Exfiltration:** the collected data goes out in the multipart `file` field shown above. Two things point to how it's packed: the binary contains **zlib/deflate** code (Adler-32 and the deflate tables), and a ChaCha20 routine is fed a key from a **Mersenne Twister** random generator. Both suggest the package is compressed and encrypted before upload, but I didn't confirm it by decrypting real traffic.

### Remote Execution

This stealer very likely can also act as a **loader** on the C2's command. The decrypted strings show payloads dropped to `%TEMP%\` as `.exe`, `.dll` or `.ps1`, and run in one of three ways:
- `CreateProcessW` (for `.exe`)
- `rundll32 "<dll>"` (for `.dll`)
- `powershell -exec bypass -f "<script>"`, or `powershell -exec bypass <command>`

There is also code that checks for `MZ` / `PE` headers and the `NtCreateThreadEx` string, which probably points to loading PE payloads straight from memory. None of this ran in the lab; it very likely needs a real task from the C2.

### Persistence and Cleanup

- **Persistence:** none observed. There's no Run key, scheduled task, Startup or service string among the recovered strings. At run time, Procmon (filtered on the loader, the injected `explorer.exe` and `cmd.exe`) showed no file writes, no registry writes and no child processes. Anything the C2 could push later is outside what I could test.
- **Mutex:** none observed. I ran stage 2 on its own under x32dbg and paused it at the C2 slot selection, which very likely comes just before its first C2 contact. At that point it held no mutex handle. A mutex created later can't be ruled out.
- **Self-delete:** the command `cmd.exe "start /min cmd.exe "/c timeout /t 3 /nobreak & del "<path>` is in the code but didn't run in the session that logged process creation. It is probably triggered by the C2 or by a specific condition.

### What capa saw (and missed)

Running capa on both stages was a useful sanity check, and a reminder to verify every match:

| capa match | Verdict |
|---|---|
| Stage 2: stackstrings, XOR, "resolve function by parsing PE exports", Mersenne Twister, clipboard | Agrees with the findings above |
| Stage 2: Adler-32 | Real: the zlib/deflate code |
| Stage 2: RC4 PRGA (6 matches in 5 functions) | False positive: a loose loop heuristic; one hit is the UTF-8 → UTF-16 converter |
| Stage 2: "get HTTP document via IWebBrowser2" | False positive: the function is the WMI BIOS / volume routine |
| Stage 1: AES, ChaCha | Very likely Go runtime code (AES-based map hashing, the runtime's ChaCha8 random generator), not the loader's own crypto |
| Stage 1: murmur3, Base64, RC4 | Not mapped to functions yet; the loader's real decode (reverse + ±0x43) is none of these |
| Stage 1: process hollowing | **Not detected.** The injection APIs are reached through Go `LazyProc` name strings, not imports |

## Conclusion

This chain pairs a cheap but effective delivery trick with a well-protected stealer. The Go loader adds almost no real protection: its symbols are intact and its "encryption" is a reversible byte encoding. It still hides the payload from import-based tooling and runs it inside a trusted, 32-bit `explorer.exe`. The stealer protects itself much better: every string has its own decoder, APIs are resolved by a custom hash, the C2 list is ChaCha20-encrypted with a stateful counter, and there's a Steam-based fallback. Its task list is probably signed with Ed25519, which would explain why the most damaging behaviour (browser and wallet theft, follow-on payloads) never appeared against a fake C2. Defenders should therefore lean on what's visible regardless of tasking: the hollowed SysWOW64 `explorer.exe` with a private RWX region, the WinHTTP `POST` pattern with the fixed Chrome 109 User-Agent, and the configuration extracted statically.

## IoCs

Network indicators are defanged here; the raw list is in [`iocs/iocs.csv`](Full GitHub link to iocs/iocs.csv).

| No. | Description | Value |
|---|---|---|
| 1 | Stage 1, Go loader (SHA256) | `a78c020b15f9950b95d5813baa198612e19ddfa6c47c22b6a379c9d09e836805` |
| 2 | Stage 2, stealer, probable Lumma (SHA256) | `7c9d4d29a0b6a623f7ae6495d75d17fb9b17c78d67f9ec9108a62f6bf39546df` |
| 3 | Stage 2 (MD5) | `5ed61e9e0c26e04d5c1f0dd7e41626f9` |
| 4 | C2 slot 0 | `convuey[.]cyou` |
| 5 | C2 slot 1 | `bendavo[.]su/asdsa` |
| 6 | C2 slot 2 | `conxmsw[.]su/vcsf` |
| 7 | C2 slot 3 | `narroxp[.]su/rewd` |
| 8 | C2 slot 4 | `squeaue[.]su/qwe` |
| 9 | C2 slot 5 | `ozonelf[.]su/asd` |
| 10 | C2 slot 6 | `exposqw[.]su/casc` |
| 11 | C2 slot 7 | `squatje[.]su/asdasd` |
| 12 | C2 slot 8 | `vicareu[.]su/bcdf` |
| 13 | Dead drop | `hxxps://steamcommunity[.]com/profiles/76561199880317058` |
| 14 | Campaign uid | `dc8e5f3081889c0e241b9a0281076771effc3817c5b1cd4ddb43b54f` |
| 15 | User-Agent | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.120 Safari/537.36` |
| 16 | Injection target | `C:\Windows\SysWOW64\explorer.exe` (created suspended by stage 1) |

## MITRE ATT&CK

| Tactic | Technique | Evidence in this post |
|---|---|---|
| Defense Evasion | T1055.012 Process Hollowing | Stage 1 → SysWOW64 `explorer.exe` |
| Defense Evasion | T1027 Obfuscated Files or Information; T1140 Deobfuscate/Decode | ±0x43 payload encoding; per-string MBA decoders; ChaCha20 config |
| Defense Evasion | T1497.001 Virtualization/Sandbox Evasion: System Checks | CPUID hypervisor vendor check (in code; its effect was not determined, and it didn't stop the sample in a VM) |
| Defense Evasion | T1027.007 Dynamic API Resolution | FNV-1a export hashing (stage 2), `LazyProc` names (stage 1) |
| Discovery | T1614.001 System Language Discovery | Russian UI-language exit |
| Discovery | T1082 System Information Discovery; T1518.001 Security Software Discovery | `Info.txt`, WMI `SecurityCenter2` |
| Execution | T1047 Windows Management Instrumentation | WMI queries (GPU, BIOS, AV) |
| Execution | T1106 Native API | Heaven's Gate stub (direct 64-bit calls from a 32-bit process; in code, not observed) |
| Collection | T1114.001 Local Email Collection | Windows Mail / Thunderbird / Outlook targets |
| Collection | T1115 Clipboard Data; T1113 Screen Capture | Imports (likely) |
| Credential Access | T1555.003 Credentials from Web Browsers; T1539 Steal Web Session Cookie | Code references (likely task-driven, not observed) |
| Command and Control | T1071.001 Web Protocols | HTTPS POST (observed) |
| Command and Control | T1102.001 Dead Drop Resolver; T1008 Fallback Channels | Steam profile; 9-slot failover (in code, not exercised at run time) |
| Exfiltration | T1041 Exfiltration Over C2 Channel | Multipart `file` upload |
| Command and Control | T1105 Ingress Tool Transfer | `%TEMP%` drop + execute (in code; likely task-driven, not observed) |

## YARA Rule

```ruby

rule Lumma_GO_Loader : loader go
{
    meta:
        description = "Go loader that rebuilds an embedded PE on the stack, decodes it and hollows SysWOW64\\explorer.exe"
        author      = "Artful Dodger"
        date        = "2026-10-10"
        hash        = "a78c020b15f9950b95d5813baa198612e19ddfa6c47c22b6a379c9d09e836805"
        status      = "TESTED"

    strings:
        // mov rdx, imm64 / mov [rsp+X], rdx / lea rdi, [rsp+Y] / lea rsi, blob / mov ecx, count / rep movsq
        $blob_builder = { 48 BA ?? ?? ?? ?? ?? ?? ?? ?? 48 89 54 24 ?? 48 8D 7C 24 ?? 48 8D 35 ?? ?? ?? ?? B9 ?? ?? ?? ?? F3 48 A5 }

        // Go symbol names kept in the binary (not stripped)
        $go1 = "main._RunPE" ascii
        $go2 = "main.RedirectToPayload" ascii
        $go3 = "main.GetImgBasePebOffset" ascii
        $go4 = "main.Wow64Set_ThreadContext" ascii
        $go5 = "main.SectionsRawToVirtual" ascii
        $go6 = "main._LoadPEModule" ascii

        // APIs reached 
        $api1 = "Wow64SetThreadContext" ascii
        $api2 = "WriteProcessMemory" ascii
        $api3 = "ResumeThread" ascii

    condition:
        uint16(0) == 0x5A4D and filesize < 10MB and
        (
            ($blob_builder and 2 of ($go*)) or
            (4 of ($go*) and all of ($api*))
        )
}

rule Lumma_GO_Payload : stealer lumma
{
    meta:
        description = "Lumma Stealer payload: ChaCha20 C2-table setup, C2 slot selection and FNV-1a (seed 0x69BBE5D1) API-hash pushes"
        author      = "Artful Dodger"
        date        = "2026-10-10"
        hash        = "7c9d4d29a0b6a623f7ae6495d75d17fb9b17c78d67f9ec9108a62f6bf39546df"
        status      = "TESTED"

    strings:
        // ChaCha20 context init: mov eax, key / mov edi, ctx+0x10 / mov ecx, 8 / xchg / rep movsd / xchg / mov eax, nonce
        $chacha_init = { B8 ?? ?? ?? ?? BF ?? ?? ?? ?? B9 08 00 00 00 96 F3 A5 96 B8 }

        // slot = byte ^ 0xF6 ; cmp 8 ; ja   (9 C2 slots, then Steam dead drop)
        $slot_select = { 0F B6 05 ?? ?? ?? ?? 34 F6 3C 08 77 }
        // shl ecx, 7 ; lea ecx, [ecx + table]   (128-byte encrypted C2 entries)
        $slot_lea    = { C1 E1 07 8D 89 }

        
        $h_settimeouts = { 68 CF BD 43 CF }   // WinHttpSetTimeouts
        $h_writedata   = { 68 AC 79 84 A7 }   // WinHttpWriteData
        $h_addheaders  = { 68 B9 1B BD 58 }   // WinHttpAddRequestHeaders

        // stack constants
        $k_uilang  = { 15 66 ED 8C }          // hash of GetUserDefaultUILanguage 
        $k_fnvseed = { 38 D5 20 53 }          // encoded FNV-1a seed (decodes to 0x69BBE5D1)

    condition:
        uint16(0) == 0x5A4D and filesize < 2MB and
        (
            ($chacha_init and $slot_select and $slot_lea) or
            (2 of ($h_*) and 1 of ($k_*) and ($chacha_init or $slot_select))
        )
}

```

## How this analysis was done

The analysis was done in an isolated Windows 10 VM with IDA Pro 9.1, x64dbg/x32dbg, Procmon, FakeNet-NG and capa. I used an AI assistant, connected to IDA Pro through MCP, for the bulk static work: annotating the decompiled code, writing the string-decryption and API-hash helpers, and drafting the unpacker and config extractor. All dynamic runs, and every conclusion in this post, are my own.

Every finding was tied to a code address or a captured artefact before it went into the report, and crypto claims were only accepted after decrypting real data from the sample. The extracted configuration was cross-checked against an independent source (any.run's config extraction for the same sample), and the tools and YARA rules were tested against both stages before publishing.

## References

1. VirusTotal
`https://www.virustotal.com/gui/file/a78c020b15f9950b95d5813baa198612e19ddfa6c47c22b6a379c9d09e836805`

2. Tools from this analysis: `go_loader.py`, `lumma_config.py`, `lumma_crypto.py` (repo `https://github.com/ArtfulDodger10/lumma-stealer-campaign`).

