# SOC Assistant CLI 🔐🛡️  
*A Command-Line Companion for SOC Analysts*

---

## 📌 Overview

SOC Assistant CLI is a Python-based Security Operations Center tool built to help analysts quickly analyze Windows Security Event IDs without switching between documentation, MITRE ATT&CK, and external references.

It provides:

- Instant event explanation  
- MITRE ATT&CK mapping  
- Severity classification  
- Structured investigation steps  
- Basic attack chain correlation  

Built using GitHub Copilot CLI to enhance structured logic, investigation mapping, and workflow optimization.

---

## 🎯 Why This Project Matters

SOC analysts often lose valuable time:

- Searching Microsoft documentation
- Checking MITRE ATT&CK website
- Writing manual triage notes
- Correlating related events manually

This tool reduces investigation time by bringing all critical triage information directly into the terminal.

⚡ Fast  
🔌 Offline  
🧠 Structured  
📊 Investigation-ready  

---

## 🚀 Features

✅ Explain Windows Security Event IDs  
✅ MITRE ATT&CK technique & tactic mapping  
✅ Severity classification (LOW / MEDIUM / HIGH / CRITICAL)  
✅ Step-by-step investigation guidance  
✅ Correlation detection (basic attack chain patterns)  
✅ Covers Top 10 high-frequency SOC Windows Events  
✅ Simple CLI interface  

---

## 🖥️ Supported Commands

```bash
python soc.py explain <EVENT_ID>
python soc.py mitre <EVENT_ID>
python soc.py severity <EVENT_ID>
python soc.py next <EVENT_ID>
python soc.py correlate "<EVENT_ID EVENT_ID EVENT_ID>"
