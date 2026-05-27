---
title: Sysmon Mirage v2
date: 2026-05-26 11:00:00 +0800
categories: [Blue Teaming]
tags: [sysmon,soc, process-injection, sigma, mitre-attack, windows-internals, syscalls, blue-team, red-team, t1055, detection-engineering, adversary-emulation, threat-hunting]
image: /assets/images/sysmon_mirage_v2_hero.png
description: "A controlled adversary emulation project covering three T1055 process injection techniques — Classic Win32 API, Direct Syscalls, and Indirect Syscalls — built from scratch in C and x64 Assembly."
---
## Introduction
Most detection engineering content on process injection explains what *should* happen.

This project focused on what *actually* happened when the code executed and the telemetry was captured directly from Sysmon.

Over the past month I built a controlled adversary emulation framework — **Sysmon Mirage v2** — covering three T1055 process injection techniques implemented from scratch in C and x64 Assembly:

- **Classic Win32 API injection** using `CreateRemoteThread`
- **Direct Syscalls** executing the `syscall` instruction directly from injector-controlled memory
- **Indirect Syscalls** borrowing the `syscall` instruction from `ntdll.dll` while preserving a custom syscall stub

The objective was intentionally narrow:

Run the same payload against the same target process using three different delivery mechanisms, capture the resulting telemetry, and compare what Sysmon actually observed at the kernel interaction layer.

Two findings directly contradicted widely published assumptions.

Those findings became more valuable than the original project itself.

---

![CallTrace Comparison]({{"/assets/images/Classic/CallTrace 10.png"}}) | ![ Comparison]({{"/assets/images/direct/EID 10 the wanted.png"}}) | ![CallTrace ]({{"/assets/images/Indirect/wanted EID 10.png"}})

*Figure 1 — EID 10 CallTrace behavior across Classic Win32 injection, Direct Syscalls, and Indirect Syscalls.*

---

## Key Findings

- Direct syscalls did **not** generate `UNKNOWN` CallTrace entries on Windows 10 with Sysmon v15.20
- Indirect syscalls still generated EID 8 `CreateRemoteThread` telemetry
- EID 10 `ProcessAccess` remained the most reliable universal detection anchor
- CallTrace integrity changed measurably across all three injection methods

---

## The Lab Environment

The testing environment was intentionally controlled to isolate telemetry differences to the injection mechanism itself rather than payload behavior.

| Component | Detail |
|---|---|
| Operating System | Windows 10 x64 |
| Sysmon Version | v15.20 — Schema 4.91 |
| EDR | None |
| Target Process | `notepad.exe` |
| Payload | x64 MessageBox shellcode |
| Injector Language | C + x64 Assembly |
| Compiler | MinGW + NASM |

No EDR was active during testing.

The purpose of the project was not bypass benchmarking. The focus was raw telemetry collection and detection engineering grounded in observable behavior rather than assumptions.

---

## The Three Injection Techniques

### Classic Win32 API Injection

Classic injection follows the documented Win32 process injection chain:

- `OpenProcess`
- `VirtualAllocEx`
- `WriteProcessMemory`
- `CreateRemoteThread`

This technique generated predictable telemetry:

- EID 1 — Process Creation
- EID 8 — CreateRemoteThread
- EID 10 — ProcessAccess

The CallTrace appeared structurally legitimate, beginning with `ntdll.dll` before descending into the injector's frames.

Detection is straightforward because the entire operation passes through heavily monitored Win32 API layers.

---

### Direct Syscalls

Direct syscalls bypass user-mode API hooks by resolving syscall numbers dynamically and executing the `syscall` instruction directly from injector memory.

The resulting EID 10 telemetry produced a visibly broken call stack.

Instead of beginning with `ntdll.dll`, the CallTrace began inside attacker-controlled injector memory.

This became the primary behavioral indicator for direct syscall execution.

---

### Indirect Syscalls

Indirect syscalls preserve the custom syscall stub while borrowing the actual `syscall` instruction from `ntdll.dll`.

At first glance the CallTrace appears more legitimate because `ntdll.dll` returns to the top of the chain.

However, injector-controlled frames remain visible deeper in the stack walk.

Sysmon still captures the transition.

---

## What the CallTrace Actually Showed

Three techniques produced three distinct CallTrace structures despite using the same payload and target process.

That distinction became the most valuable telemetry artifact in the project.

---

### Classic Injection — EID 10

```text
C:\WINDOWS\SYSTEM32\ntdll.dll+9da64|
C:\WINDOWS\System32\KERNELBASE.dll+28d3e|
C:\Users\Artful Dodger\Desktop\Injectors\classic_injection.exe+1651|
C:\Users\Artful Dodger\Desktop\Injectors\classic_injection.exe+12fe|
C:\Users\Artful Dodger\Desktop\Injectors\classic_injection.exe+1416|
C:\WINDOWS\System32\KERNEL32.DLL +17374|
C:\WINDOWS\SYSTEM32\ntdll.dll+4cc91

GrantedAccess: 0x142A
```

The injector appears relatively deep within an otherwise legitimate-looking stack.

Classic injection relies on the Win32 layer and makes no attempt to conceal stack structure.

---


### Direct Syscalls — EID 10

```text
C:\Users\Artful Dodger\Desktop\Injectors\direct\directSysCall.exe+1b0b|
C:\Users\ArtfulDodger\Desktop\Injectors\direct\directSysCall.exe+1858|
C:\Users\Artful Dodger\Desktop\Injectors\direct\directSysCall.exe+1ab8|
C:\Users\Artful Dodger\Desktop\Injectors\direct\directSysCall.exe+12fe|
C:\Users\Artful Dodger\Desktop\Injectors\direct\directSysCall.exe+1416
C:\WINDOWS\System32\KERNEL32.DLL+17374|
C:\WINDOWS\SYSTEM32\ntdll.dll+4cc91

GrantedAccess: 0x103A
```

The injector appears at the very top of the stack.

`ntdll.dll` is absent from the expected leading position.

That broken stack integrity became the strongest detection signal for direct syscall execution.

---


### Indirect Syscalls — EID 10

```text
C:\WINDOWS\SYSTEM32\ntdll.dll+9da64|
C:\Users\Artful Dodger\Desktop\Injectors\indirect\indirectSysCall.exe+1945|
C:\Users\Artful Dodger\Desktop\Injectors\indirect\indirectSysCall.exe+1b97|
C:\Users\Artful Dodger\Desktop\Injectors\indirect\indirectSysCall.exe+12fe|
C:\Users\Artful Dodger\Desktop\Injectors\indirect\indirectSysCall.exe+1416|
C:\WINDOWS\System32\KERNEL32.DLL+17374|
C:\WINDOWS\SYSTEM32\ntdll.dll+4cc91

GrantedAccess: 0x103A
```

`ntdll.dll` returns to the top of the stack, but the injector's own frames remain visible mid-chain.

The stack appears cleaner than direct syscalls, but it is still distinguishable from legitimate behavior.

---

## Finding 1 — `UNKNOWN` Never Appeared

> **Finding:** Modern Sysmon versions did not produce `UNKNOWN` CallTrace entries for direct syscalls.

Before testing began, the original detection hypothesis focused heavily on `UNKNOWN` entries appearing in the CallTrace field during direct syscall execution.

That pattern never appeared.

Not once.

Not across repeated executions on Windows 10 using Sysmon v15.20.

Instead, the consistent signal was the injector's own executable path appearing at the top of the stack walk.

This changes how direct syscall detections should be structured on modern systems.

Detection rules relying primarily on:

```text
CallTrace contains UNKNOWN
```

will fail silently in this environment.

The final Sigma logic was rewritten to prioritize broken stack integrity and injector-controlled memory frames instead.

---



## Finding 2 — Indirect Syscalls Still Generated EID 8

> **Finding:** Indirect syscalls still generated CreateRemoteThread telemetry.

This contradicted nearly every public explanation surrounding indirect syscall execution.

The common assumption is:

- Win32 APIs generate EID 8
- Direct and indirect syscalls bypass EID 8 entirely

That assumption did not hold during testing.

Every indirect syscall execution produced:

- EID 8 — `CreateRemoteThread`

with:

```text
StartModule: -
```

The most likely explanation is that Sysmon's kernel callback mechanism captures thread creation independently of whether the request originated through Win32 APIs or syscall execution.

The underlying kernel operation remains identical.

That has two important implications:

1. EID 8 has broader detection coverage than commonly documented
2. Absence of EID 8 should not be treated as evidence of advanced syscall-based injection

---

![Indirect Syscall EID 8]({{"/assets/images/Indirect/EID 8.png"}})

*— Indirect syscall execution still generating EID 8 CreateRemoteThread telemetry.*

---

## EID 10 as the Universal Detection Anchor

Across all three techniques, one event remained completely consistent:

- EID 10 — `ProcessAccess`

Every injection method required privileged access to the target process before execution could occur.

That access request consistently generated telemetry regardless of how advanced the injection mechanism became.

This made EID 10 the most reliable behavioral anchor for T1055 detection engineering.

---

| Injection Technique | Observed GrantedAccess | Notes |
|---|---|---|
| Classic Win32 API | `0142A` | Standard CreateRemoteThread flow |
| Direct Syscalls | `0x103A` | Broken CallTrace integrity |
| Indirect Syscalls | `0x103A` | ntdll restored at stack top |

---

The direct syscall injector also generated a separate low-privilege WTS enumeration event before injection occurred.

That sequence created a useful behavioral chain:

1. Process enumeration
2. Privileged handle acquisition
3. Remote thread execution

The telemetry sequence itself became detectable.

---



## Where Detection Breaks Down

No detection framework is complete without documenting where it fails.

Several important limitations emerged during testing.

---

### Memory Allocation and Write Operations Remain Invisible

`VirtualAllocEx` and `NtWriteVirtualMemory` generated no direct Sysmon telemetry.

By the time EID 10 appears, the payload has already been written into the remote process.

The detection occurs after compromise activity has already begun.

---

### Stack Spoofing Defeats CallTrace Analysis

CallTrace-based detection assumes stack integrity remains intact during Sysmon's stack walk.

An injector implementing stack spoofing can replace or manipulate stack frames before telemetry capture occurs.

When that happens:

- direct syscalls can resemble legitimate API activity
- indirect syscalls become significantly harder to distinguish
- CallTrace reliability degrades rapidly

---

### BYOVD Removes Sysmon Visibility Entirely

Bring Your Own Vulnerable Driver attacks can unregister Sysmon kernel callbacks completely.

In that scenario:

- the injector still executes
- the system appears healthy
- telemetry collection silently stops

Understanding where telemetry disappears is as important as understanding where it exists.

---

## The Detection Rules

Three Sigma rules were built directly from observed telemetry patterns.

| Rule | Primary Selector | Confidence |
|---|---|---|
| `win_classic_win32_injection.yml` | EID 8 + `StartModule: -` | High |
| `win_direct_syscall_injection.yml` | Broken CallTrace integrity | High |
| `win_indirect_syscall_injection.yml` | ntdll-top with injector mid-chain | Medium |

---

The final rules intentionally avoided assumptions tied to:

- specific execution paths
- user directories
- hardcoded injector names
- `UNKNOWN` stack artifacts

The focus remained behavioral rather than environmental.

---

## Lessons Learned

The most valuable outcome of the project was not the injection framework itself.

It was the gap between documentation and reality.

Patterns repeatedly described in public resources failed to appear during testing, while other telemetry artifacts consistently emerged despite claims that they should not exist.

The practical lesson was simple:

Documentation is not ground truth.

Telemetry is.

Reliable detection engineering begins with direct observation inside controlled environments rather than assumptions inherited from older research.

---



## Repository

The complete research project — including injector implementations, Sysmon configuration, Sigma detection rules, telemetry analysis, and supporting documentation — is available on GitHub:

[Sysmon Mirage v2 — GitHub Repository](https://github.com/ArtfulDodger10/sysmon-mirage-v2)