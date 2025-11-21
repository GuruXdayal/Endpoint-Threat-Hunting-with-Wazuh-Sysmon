# 🛡️ **Endpoint-Threat-Hunting-with-Wazuh-Sysmon**

### *End-to-end Windows threat hunting using Sysmon telemetry, Wazuh SIEM, and Atomic Red Team.*

---

## 🚀 **Project Summary**

This project demonstrates **real-world Windows threat hunting workflows**, from hypothesis → attack simulation → telemetry validation → hunting queries → detection analysis.
Built using **Sysmon**, **Wazuh SIEM**, and **Atomic Red Team**, this lab mirrors the investigation patterns used by SOC teams to detect credential theft, PowerShell abuse, LOLBAS execution, and malicious user-initiated actions.

This repository documents **how I planned, simulated, hunted, validated, and analyzed** three MITRE ATT&CK–mapped behaviors — written in a style that reflects *how a SOC analyst investigates real intrusions*.

---

## 🧩 **Tools & Telemetry Stack**

| Badge                                                                                         | Description                                                                                            |
| --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| ![Sysmon](https://img.shields.io/badge/Sysmon-v15.15-blue?logo=windows)                       | Captured high-fidelity endpoint telemetry (process creation, file events, registry, network activity). |
| ![Wazuh](https://img.shields.io/badge/Wazuh-SIEM-green?logo=wazuh)                            | Served as my SIEM for log ingestion, visual queries, and custom detection rules.                       |
| ![Atomic Red Team](https://img.shields.io/badge/Atomic%20Red%20Team-ATT%26CK-red?logo=redhat) | Used to simulate real adversary tradecraft mapped to MITRE techniques.                                 |

---

## 🎯 **Why This Project Matters (Hiring Manager Perspective)**

A SOC Analyst must be able to:

✔ Recognize malicious behavior using endpoint telemetry
✔ Map activity to MITRE ATT&CK techniques
✔ Form hypotheses and hunt across data
✔ Validate detection logic and highlight gaps
✔ Document investigations clearly

This project demonstrates **all five**, with complete hunting pipelines for **three real attack behaviors**.

Rather than simply “running Atomic tests,” I focused on **understanding why the behavior is malicious**, what telemetry should appear, how to query for it, and how to reason about detection gaps and mitigation.

---

## 🧠 **How This Project Strengthened My SOC Skillset**

* Built **full investigation pipelines** for each scenario: hypothesis → simulation → hunt → validate.
* Learned to interpret **Sysmon Event IDs (1,3,11,12)** and map them to adversary behaviors.
* Practiced **query building in Wazuh Discover**, including filtering parent/child process relationships.
* Created **custom Wazuh rules** when default detections were missing.
* Improved ability to **triage suspicious PowerShell and LOLBAS activity**.
* Built a repeatable structure for threat-hunting documentation used by real SOC teams.

---

## 🤖 **How AI Helped Accelerate the Project**

AI tools like **ChatGPT, Grok, and Claude** significantly accelerated my workflow by:

* Helping refine **hypotheses** based on MITRE ATT&CK intelligence
* Explaining Sysmon event behavior and detection logic
* Assisting with **query construction** and tuning
* Troubleshooting errors during telemetry collection
* Improving clarity and structure of documentation for this repo

AI did *not* automate the project — it enhanced my learning and helped me move faster while maintaining accuracy.

---

## 🔥 **Threat Hunting Scenarios (Fully Documented)**

Each scenario contains:
✔ Hypothesis
✔ Intelligence & context
✔ Attack simulation steps (Atomic Red Team)
✔ Sysmon evidence
✔ Wazuh hunting queries
✔ Detection results
✔ Analyst notes & recommendations
✔ Screenshots (exec + telemetry + SIEM results)

---

### 🔗 **Scenario 1 — LSASS Credential Dumping (T1003.001)**

➡️ [View Complete Scenario Documentation](./LSASS%20Credential%20Dumping/README.md)
**Objective:** Detect credential theft attempts targeting LSASS using ProcDump, comsvcs.dll, and NanoDump.

---

### 🔗 **Scenario 2 — PowerShell Abuse (T1059.001)**

➡️ [View Complete Scenario Documentation](./Command%20&%20Scripting%20Interpreter%20—%20PowerShell/README.md)
**Objective:** Hunt for suspicious PowerShell execution including memory-loaded scripts, XML download cradles, and mshta-based payload retrieval.

---

### 🔗 **Scenario 3 — User Execution: Malicious File (T1204.002)**

➡️ [View Complete Scenario Documentation](./User%20Execution-Malicious%20File/README.md)
**Objective:** Detect malicious file execution patterns such as PUAs, LNK-based payload downloads, and ClickFix RunMRU → mshta abuse.

---

## 🏗️ **Repository Structure**

```
📁 Endpoint-Threat-Hunting-with-Wazuh-Sysmon
│
├── 1_LSASS_Dumping/           # Scenario 1 full documentation
├── 2_PowerShell_Abuse/        # Scenario 2 full documentation
├── 3_User_Execution/          # Scenario 3 full documentation
│
└── README.md                  # Face of the repo (this file)
```

---

## 🌟 **Key Takeaways**

* Learned how attackers abuse PowerShell, LOLBAS tools, and Windows components.
* Strengthened endpoint analysis skills using **Sysmon + Wazuh**.
* Improved ability to map real events to **MITRE ATT&CK** techniques.
* Practiced building repeatable **investigative workflows**.
* Enhanced triage speed and analysis clarity through AI-assisted reasoning.

---

## 📬 Connect with Me

Let’s connect and discuss cybersecurity, AI, and blue-team innovation 👇  
[![LinkedIn Badge](https://img.shields.io/badge/LinkedIn-Connect-blue?logo=linkedin&style=flat-square)](https://www.linkedin.com/in/gurudayal-cybersecurity/)
