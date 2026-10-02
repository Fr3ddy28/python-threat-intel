# Automated Python Threat Intelligence IP Parser

## Overview
A lightweight Python automation tool designed for Security Operations Center (SOC) analysts to streamline log analysis and incident triage. The script queries the **AbuseIPDB REST API v2** to pull real-time threat intelligence metrics and evaluate malicious IP reputation scores.

---

## Features
- **API Integration:** Connects to AbuseIPDB REST API v2 endpoints.
- **Data Parsing:** Parses JSON response payloads into structured threat reports.
- **Risk Assessment:** Evaluates abuse confidence scores and generates triage recommendations (Critical, Warning, Info).
- **CLI Support:** Accepts IP addresses via command-line arguments for quick analyst execution during triage.

---

## Technical Stack & Dependencies
- **Language:** Python 3.x
- **Libraries:** `requests`, `json`, `sys`

---

## Installation & Usage

### 1. Prerequisites
Install required Python dependencies:
```bash
pip install requests
```

### 2. Execution
Run the script passing an IP address as an argument:
```bash
python threat_intel.py 185.220.101.5
```

---

## Sample Execution Output

```text
[*] Triaging IP Address: 185.220.101.5...

=================== Threat Intelligence Summary ===================
IP Address:            185.220.101.5
Abuse Confidence Score:100%
Country Code:          DE
ISP / Domain:          Tor Exit Node
Total Threat Reports:  4820
Whitelisted:           False
===================================================================

[CRITICAL] IP score exceeds threshold (>80%). Immediate containment recommended.
```
