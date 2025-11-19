
# 🔍 Understanding LSASS Credential Dumping (T1003.001)

**Credential dumping** is one of the most critical post-exploitation techniques used by attackers.
Its goal is to extract authentication material such as:

* NTLM hashes
* Kerberos tickets
* Plaintext passwords
* Cached credentials

Windows stores these secrets inside **LSASS.exe (Local Security Authority Subsystem Service)**.
If an adversary can dump LSASS memory, they can:

* Impersonate users
* Escalate privileges
* Move laterally throughout the network

This makes **LSASS dumping (T1003.001)** one of the *highest-impact* techniques in MITRE ATT&CK.

---

# ⚔️ Why I Performed Three LSASS Dumping Simulations

Attackers use multiple methods to dump LSASS, depending on stealth, tooling, and privileges.
To emulate realistic adversary behavior, I executed **three different Atomic Red Team tests**, each representing unique TTPs.

---

## 🧪 Test 1 — ProcDump LSASS Dump (T1003.001)

**Purpose:**
Simulates a very common technique using Microsoft’s Sysinternals ProcDump.

**What it does:**
Runs:

```
procdump.exe -ma lsass.exe C:\Windows\Temp\lsass_dump.dmp
```

This creates a full memory dump of LSASS.

**Why attackers use it:**
ProcDump is *signed by Microsoft*, making it blend into normal Windows activity.

---

## 🧪 Test 2 — LSASS Dump via comsvcs.dll (rundll32)

**Purpose:**
Simulates a stealthy LSASS dump using **LOLBAS (Living-off-the-land binaries)**.

**What it does:**
Executes:

```
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump lsass.exe <dump path>
```

Uses built-in Windows DLLs — **no external tool required**.

**Why attackers use it:**
This method is *more evasive*, because both `rundll32.exe` and `comsvcs.dll` are trusted binaries.

---

## 🧪 Test 4 — NanoDump (Stealth Credential Dumping)

**Purpose:**
Simulates a modern, highly evasive LSASS dumping technique.

**What it does:**
NanoDump:

* Uses direct system calls
* Avoids standard API monitoring
* Dumps LSASS memory stealthily
* Writes `nanodump.dmp` or similar output

**Why attackers use it:**
NanoDump is specifically designed to **evade EDR**, making it a favorite in real offensive operations.

---

# 🎯 Why These Three Tests Matter (SOC Analyst Perspective)

| Test                     | Technique Type         | Difficulty to Detect | Why It Matters                    |
| ------------------------ | ---------------------- | -------------------- | --------------------------------- |
| **ProcDump**             | Signed external tool   | ⭐ Easy               | Used heavily by ransomware groups |
| **comsvcs.dll (LOLBin)** | Living-off-the-land    | ⭐⭐ Medium            | Blends with legitimate binaries   |
| **NanoDump**             | Direct syscall dumping | ⭐⭐⭐ Hard             | Modern APT & red-team behavior    |

Performing all three demonstrates that I can:

✔ Understand multiple attacker TTP variations
✔ Hunt across different log patterns
✔ Use Sysmon + SIEM telemetry effectively
✔ Map behavior to MITRE ATT&CK
✔ Build detections for different tradecraft levels
---
# **Scenario 1 – LSASS Credential Dumping (T1003.001)**

Using **full Threat Hunting Methodology**,
using **your exact commands, your exact telemetry, your screenshots**,
and formatted exactly like a **real SOC case study**.

---

# 📂 **Scenario 1 — LSASS Credential Dumping (T1003.001)**

**Category:** Credential Access
**Technique:** OS Credential Dumping
**Sub-Technique:** LSASS Memory Dump (T1003.001)
**Platform:** Windows 10
**Tools Used:** Sysmon, Wazuh, Atomic Red Team

---

# 🧠 **0. Hypothesis**

> *“If an attacker attempts credential dumping on the Windows endpoint, they may access LSASS memory using tools like ProcDump, Rundll32 (comsvcs.dll), or Nanodump.
> Such actions should generate Sysmon Event ID 10/1 and can be hunted through Wazuh Discover. Therefore, I should detect an abnormal process accessing `lsass.exe` and validate it through threat hunting queries.”*

---

# 🎯 **1. Intelligence & Context — Why This Hunt Matters**

Credential dumping is a **critical step** in nearly every Windows intrusion:

* Ransomware operators extract domain hashes to move laterally
* Red teams use ProcDump/NanoDump to pull credentials
* Threat actors (FIN6, APT29) regularly target LSASS

Detecting LSASS memory access is one of the **highest-value hunts** in real SOC operations.

---

# 🔬 **2. Attack Simulations (T1003.001) — What I Tested**

To mimic realistic adversary behaviors, I executed **three Atomic Red Team simulations**, each representing a *different attacker method*.

### **🧪 Test 1 — ProcDump LSASS Dump**

```
Invoke-AtomicTest T1003.001 -TestNumbers 1
```

✔ Creates `lsass_dump.dmp` using Sysinternals procdump.exe
✔ Common technique used by ransomware operators

### **🧪 Test 2 — comsvcs.dll via rundll32**

```
Invoke-AtomicTest T1003.001 -TestNumbers 2
```

✔ Uses legitimate signed DLL to dump LSASS
✔ Harder to detect because it uses built-in Windows components

### **🧪 Test 4 — NanoDump**

```
Invoke-AtomicTest T1003.001 -TestNumbers 4
```

✔ Evasion-friendly and very stealthy
✔ Heavily used in modern malware/red teaming

---

# 🧩 **3. Data Source Validation**

Before hunting, I validated:

✔ Sysmon v15.15 (SwiftOnSecurity config) running
✔ Wazuh Windows agent active
✔ Event IDs 1 and 10 being collected
✔ Logs successfully sent → Wazuh Manager

📌 Screenshot:
`/screenshots/02_agent_status.png`

---

# 🔥 **4. Telemetry Collected (Sysmon Evidence)**

From Wazuh Discover → Sysmon logs, I captured the following fields:

### **Example Sysmon Event from Test 1 (ProcDump)**

| Field           | Value                                                                                                     |
| --------------- | --------------------------------------------------------------------------------------------------------- |
| **Image**       | `C:\AtomicRedTeam\ExternalPayloads\procdump.exe`                                                          |
| **TargetImage** | `lsass.exe`                                                                                               |
| **ProcessId**   | `2912`                                                                                                    |
| **User**        | `DESKTOP-LL7DT1T\lus3r`                                                                                   |
| **CommandLine** | `C:\AtomicRedTeam\ExternalPayloads\procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass_dump.dmp` |
| **SHA256**      | `D824E2FB30315B71F7063052EB847BA6A3D6B98A5A0B8F0E1350EDB7968ED582`                                        |

📌 Screenshot:
`/screenshots/03_sysmon_event.png`

This confirms LSASS access via ProcDump.

---

# 🕵️ **5. Threat Hunting Queries (Wazuh Discover)**

I used the following Wazuh KQL-style queries to confirm suspicious LSASS access.

### **🔍 Query 1 — General LSASS Access**

```
data.win.eventdata.parentImage:*procdump* OR
data.win.eventdata.parentCommandLine:*lsass.exe*
```

**Result:** Shows ProcDump accessing LSASS.

---

### **🔍 Query 2 — Rundll32 Dump (Test 2)**

```
data.win.eventdata.image:*rundll32* AND
data.win.eventdata.parentCommandLine:*lsass*
```

**Result:** Detects comsvcs.dll LSASS dump.

---

### **🔍 Query 3 — Nanodump Behavior (Test 4)**

```
data.win.eventdata.parentImage:*powershell* AND
data.win.eventdata.commandLine:*nanodump*
```

**Result:** Detects NanoDump as expected.

📌 Screenshot:
`/screenshots/04_hunting_queries.png`

---

# 🚨 **6. Wazuh Detection (SIEM Alerts)**

### ✔ Initially: **No Alerts**

Sysmon captured activity, but Wazuh → **no alerts fired**.

This revealed a **detection gap** — very realistic in threat hunting.

### ✔ I Created Custom Wazuh Rules

After adding LSASS detection rules to Wazuh Manager:

**Rule ID:** `100312`
**Description:** `T1003.001 Dump Command`

Wazuh began detecting LSASS dump attempts.

📌 Screenshot:
`/screenshots/05_wazuh_alerts.png`

---

# 🧠 **7. Hypothesis Validation (Final Result)**

### **✔ Hypothesis Proven TRUE**

**ProcDump, Rundll32, and Nanodump were all recorded as unauthorized access attempts to LSASS.exe**, confirmed by:

* Sysmon Event ID 1/10
* Process access telemetry
* Suspicious parent-child relationships
* CommandLine including lsass.exe

---

# 📝 **8. Analyst Notes (My SOC Findings)**

* ProcDump, Rundll32, and Nanodump attempted LSASS memory access.
* This is an extremely high-risk activity → leads to credential theft.
* The behavior matches MITRE ATT&CK T1003.001.
* Legitimate processes rarely, if ever, access LSASS.
* Sysmon clearly logged the behavior; SIEM alerts needed tuning.

---

# 🛡️ **9. Detection Gap Identified**

> *Sysmon captured LSASS access, but Wazuh SIEM did not generate an alert until I added custom rules.*

This is a **realistic SOC insight** — detection engineering is required to catch LSASS credential dumping.

---

# 🛠️ **10. Mitigation Recommendation**

* Enable **Credential Guard**
* Block non-admin LSASS access via LSASS protection
* Monitor process access rights frequently
* Enable additional logging (ScriptBlock + AMSI)

---

# 🧩 **11. Summary — What I Learned**

* How attackers dump LSASS using multiple TTPs (ProcDump, Rundll32, NanoDump)
* How Sysmon logs memory access patterns
* How to structure a real Threat Hunt using hypothesis-driven methodology
* How to identify SIEM detection gaps and build custom rules
* How to correlate parent-child processes for credential access attacks

---



