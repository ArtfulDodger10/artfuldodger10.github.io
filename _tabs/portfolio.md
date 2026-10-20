---
title: Portfolio
icon: fas fa-briefcase
order: 0
---

I reverse malware end to end: from the delivery chain to the final payload, then turn
what I find into tools and detections other analysts can reuse. Each project below has
a write-up and a public repo with the extractors, YARA rules, IOCs and ATT&CK mapping.

## Malware analysis

### Lumma Stealer: two delivery chains, one config extractor
Two unrelated loaders, a **Go loader** and a **C++ crypter** hidden in a fake "AIO Checker"
tool, both delivering Lumma Stealer. The second chain also drops a .NET crypto clipper.
The Lumma payloads store their C2 table the same way, so **one static extractor handles
both**, from the file on disk or from a memory dump of the hollowed process.

**Shows:** Go and C++ reversing, RC4 payload decryption, process hollowing, config extraction.

[Go loader write-up]({% post_url 2026-10-10-Lumma-GO-Analysis %}) ·
[C++ crypter write-up]({% post_url 2026-10-11-Lumma-crypter-Analysis %}) ·
[Code & IOCs](https://github.com/ArtfulDodger10/lumma-stealer-campaign)

### XWorm V7.1: from phishing email to RAT
A September 2026 phishing campaign: RAR, then a JavaScript dropper, then a PowerShell loader,
ending with XWorm hollowed into `MSBuild.exe`. I recovered the config encryption scheme
(AES-256-ECB with a key derived from the mutex) and built a **static config extractor
tested on 9 payloads from V3.0 to V7.4**.

**Shows:** .NET reversing, script deobfuscation, crypto recovery, tooling.

[Campaign write-up]({% post_url 2026-9-6-Xworm-Analysis %}) ·
[VBScript downloader write-up]({% post_url 2026-7-31-XWorm-RAT-Malware-Analysis %}) ·
[Code & IOCs](https://github.com/ArtfulDodger10/XWorm-Analysis)

### AgentTesla: multi-stage loader to SMTP exfiltration
The full loader chain, steganographic payload recovery, process hollowing, and the
extraction of the SMTP settings the stealer uses to send stolen data.

**Shows:** multi-stage .NET unpacking, payload recovery, config extraction.

[Write-up]({% post_url 2026-06-16-AgentTesla-RAT-Full-Malware-Analysis-Report %})

## Detection engineering

### YARA rules
Rules for families I have reversed (XWorm, AgentTesla, AsyncRAT), each written from my
own analysis with notes on why each string was chosen, and **false-positive tested against
clean Windows files** before being added.

[Rules repo](https://github.com/ArtfulDodger10/yara-rules)

### Sysmon Mirage v2: what injection telemetry survives
Three T1055 process injection techniques written from scratch in C and x64 assembly
(classic Win32 API, direct syscalls, indirect syscalls), run against the same target to
measure which Sysmon telemetry survives each step toward stealth, and where detection breaks.

**Shows:** Windows internals, adversary emulation, detection logic built from observed telemetry.

[Write-up]({% post_url 2026-05-27-Sysmon-mirage-v2 %}) ·
[Code](https://github.com/ArtfulDodger10/sysmon-mirage-v2)

## Reverse engineering fundamentals

### Manual unpacking of 64-bit UPX binaries
Five ways to unpack the same binary by hand: tail jump, memory write, DEP trick, call stack
backtracing, and injecting the payload into allocated memory.

[Write-up]({% post_url 2026-04-14-manual-unpacking %})

---

[About me](/about/) · [GitHub](https://github.com/ArtfulDodger10) ·
[LinkedIn](https://www.linkedin.com/in/nader-ayman-569358286/) ·
[Email](mailto:naderelsehrawii@gmail.com)
