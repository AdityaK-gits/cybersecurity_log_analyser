


🛡️ Cybersecurity Log Analyzer

A Python-based Cybersecurity Log Analyzer that detects suspicious activity such as brute-force attacks, SQL injections, DoS attempts, and access from blacklisted IPs — all from system/application log data.
It includes both a Command-Line Tool and an Interactive Web Dashboard built with Streamlit.

⚙️ Features

✅ Threat Detection

🟥 SQL Injection

🟧 Brute Force Attack

🟪 DoS (Denial of Service) Attack

🟨 Access from Blacklisted IPs

🟦 Sensitive File Access

✅ Reporting & Visualization

Auto-generated security reports in .txt and .json formats

Interactive dashboard UI (via Streamlit)

Downloadable reports for easy sharing

✅ Extras

Built entirely using Python Standard Library

No external dependencies (for CLI version)

Generates realistic sample log data for simulation

🧠 How It Works

The analyzer reads log files line by line, parses events, and runs detection checks such as:

Pattern-matching SQL keywords (UNION SELECT, DROP TABLE, etc.)

Counting failed logins in short time windows

Identifying frequent requests from the same IP (DoS behavior)

Checking IPs against a blacklist

Flagging access to sensitive files

🧾 Example Output (Console)
🟡[MEDIUM ALERT] BLACKLISTED_IP: Access from blacklisted IP 123.45.67.89 by user eve
🔴[HIGH ALERT] BRUTE_FORCE_ATTACK: Possible brute force attack from 123.45.67.89 - 5 failed attempts in 2 minutes
🟣[CRITICAL ALERT] DOS_ATTACK: Possible DoS attack from 203.0.113.12 - 102 requests in 10 seconds

Processed 985/1000 log entries
Total alerts generated: 27

🔒 Analysis complete! Check security_report.txt for detailed findings.
🗂️ Project Structure
cybersecurity_log_analyser/
│
├── log_analyzer.py          # Core log analysis engine (CLI)
├── app.py                   # Streamlit UI for interactive use
├── requirements.txt         # Dependencies (Streamlit only)
├── sample_logs.log          # Example generated logs
├── security_report.txt      # Example report output
├── alerts.json              # JSON-formatted alert output
└── README.md                # Project documentation

📊 Example Streamlit UI

🧩 Dashboard Preview:
<img width="1359" height="574" alt="Screenshot 2025-10-22 202840" src="https://github.com/user-attachments/assets/1a9532e5-e36b-4b82-b516-28095fef2d92" />

<img width="1281" height="434" alt="Screenshot 2025-10-22 200432" src="https://github.com/user-attachments/assets/52f9887e-ff5b-4a2c-a4be-98ea9323a769" />
🧑‍💻 Author

👤 Aditya Kolluru
💼 B.Tech CSE | Cybersecurity & AI Enthusiast
📍 MS Ramaiah University of Applied Sciences

🌐 Streamlit Web App (Interactive UI)

Launch the web dashboard:

https://cybersecurityloganalyser-fa2enc9yd6rar9tesypg22.streamlit.app/


⭐ Future Enhancements

Add visualization charts for alert distribution

Build Flask API for integration

Implement live log monitoring

# Cybersecurity Log Analyzer - Expected Output Examples

## 1. Initial Setup and Log Generation

### Command:
```bash
python log_analyzer.py --generate --num-logs 1000
```

### Expected Output:
```
Generating 1000 sample log entries...
Sample logs generated successfully: sample_logs.log
Log file sample_logs.log not found. Use --generate to create sample logs.
```

---

## 2. Full Analysis Run (Generate + Analyze)

### Command:
```bash
python log_analyzer.py --generate --logs sample_logs.log --report security_report.txt
```

### Expected Console Output:
```
Generating 1000 sample log entries...
Sample logs generated successfully: sample_logs.log
Analyzing log file: sample_logs.log
============================================================

🟡[MEDIUM ALERT] BLACKLISTED_IP: Access from blacklisted IP 123.45.67.89 by user eve
🔴[HIGH ALERT] BRUTE_FORCE_ATTACK: Possible brute force attack from 123.45.67.89 - 5 failed attempts in 2 minutes
🟡[MEDIUM ALERT] BLACKLISTED_IP: Access from blacklisted IP 192.168.1.100 by user admin
🔴[HIGH ALERT] SQL_INJECTION: SQL injection attempt detected from 192.168.1.100 by user guest
🟡[MEDIUM ALERT] SENSITIVE_FILE_ACCESS: Access to sensitive file /etc/passwd from 192.168.1.100 by user alice
🔴[HIGH ALERT] BRUTE_FORCE_ATTACK: Possible brute force attack from 192.168.1.100 - 6 failed attempts in 2 minutes
🔴[HIGH ALERT] SQL_INJECTION: SQL injection attempt detected from 123.45.67.89 by user bob
🟡[MEDIUM ALERT] BLACKLISTED_IP: Access from blacklisted IP 203.0.113.12 by user john
🟣[CRITICAL ALERT] DOS_ATTACK: Possible DoS attack from 203.0.113.12 - 102 requests in 10 seconds
🟡[MEDIUM ALERT] SENSITIVE_FILE_ACCESS: Access to sensitive file /etc/shadow from 172.16.1.50 by user admin
🔴[HIGH ALERT] EXCESSIVE_FILE_ACCESS: Excessive file access from 192.168.1.100 - 21 attempts in 5 minutes

Processed 985/1000 log entries
Total alerts generated: 27

Generating security report: security_report.txt
Report saved to: security_report.txt
Alerts saved to: alerts.json

🔒 Analysis complete! Check security_report.txt for detailed findings.
```

---

## 3. Security Report Content

### File: `security_report.txt`
```
CYBERSECURITY LOG ANALYSIS REPORT
==================================================
Generated: 2025-08-20 14:30:45

ALERT SUMMARY
--------------------
BLACKLISTED_IP: 8
BRUTE_FORCE_ATTACK: 4
SQL_INJECTION: 6
SENSITIVE_FILE_ACCESS: 5
DOS_ATTACK: 2
EXCESSIVE_FILE_ACCESS: 2

SEVERITY BREAKDOWN
--------------------
HIGH: 12
MEDIUM: 13
CRITICAL: 2

DETAILED ALERTS
--------------------
[2025-08-20 14:30:44] CRITICAL - DOS_ATTACK: Possible DoS attack from 203.0.113.12 - 102 requests in 10 seconds
[2025-08-20 14:30:43] HIGH - EXCESSIVE_FILE_ACCESS: Excessive file access from 192.168.1.100 - 21 attempts in 5 minutes
[2025-08-20 14:30:42] HIGH - SQL_INJECTION: SQL injection attempt detected from 123.45.67.89 by user bob
[2025-08-20 14:30:41] HIGH - BRUTE_FORCE_ATTACK: Possible brute force attack from 192.168.1.100 - 6 failed attempts in 2 minutes
[2025-08-20 14:30:40] MEDIUM - SENSITIVE_FILE_ACCESS: Access to sensitive file /etc/passwd from 192.168.1.100 by user alice
[2025-08-20 14:30:39] HIGH - SQL_INJECTION: SQL injection attempt detected from 192.168.1.100 by user guest
[2025-08-20 14:30:38] MEDIUM - BLACKLISTED_IP: Access from blacklisted IP 192.168.1.100 by user admin
[2025-08-20 14:30:37] HIGH - BRUTE_FORCE_ATTACK: Possible brute force attack from 123.45.67.89 - 5 failed attempts in 2 minutes
[2025-08-20 14:30:36] MEDIUM - BLACKLISTED_IP: Access from blacklisted IP 123.45.67.89 by user eve

TOP SUSPICIOUS IPs
--------------------
192.168.1.100: 8 alerts
123.45.67.89: 6 alerts
203.0.113.12: 4 alerts
172.16.1.50: 3 alerts
10.0.0.5: 2 alerts
```

---

## 4. Specific Test Case Examples

### 4.1 Brute Force Attack Detection

**Sample Log Entries:**
```
2025-08-20 12:40:21 LOGIN FAILED user=admin ip=123.45.67.89
2025-08-20 12:40:35 LOGIN FAILED user=admin ip=123.45.67.89
2025-08-20 12:40:48 LOGIN FAILED user=root ip=123.45.67.89
2025-08-20 12:41:02 LOGIN FAILED user=guest ip=123.45.67.89
2025-08-20 12:41:15 LOGIN FAILED user=user1 ip=123.45.67.89
```

**Expected Output:**
```
🔴[HIGH ALERT] BRUTE_FORCE_ATTACK: Possible brute force attack from 123.45.67.89 - 5 failed attempts in 2 minutes
```

---

### 4.2 SQL Injection Detection

**Sample Log Entries:**
```
2025-08-20 12:42:01 QUERY "SELECT * FROM users WHERE username='admin' OR '1'='1'" user=hacker ip=192.168.1.100
2025-08-20 12:42:15 QUERY "SELECT * FROM accounts UNION SELECT password FROM admin" user=attacker ip=203.0.113.1
2025-08-20 12:42:30 QUERY "DROP TABLE users; --" user=malicious ip=123.45.67.89
```

**Expected Output:**
```
🔴[HIGH ALERT] SQL_INJECTION: SQL injection attempt detected from 192.168.1.100 by user hacker
🔴[HIGH ALERT] SQL_INJECTION: SQL injection attempt detected from 203.0.113.1 by user attacker
🔴[HIGH ALERT] SQL_INJECTION: SQL injection attempt detected from 123.45.67.89 by user malicious
```

---

### 4.3 DoS Attack Detection

**Sample Log Entries:**
```
2025-08-20 12:45:00 REQUEST /api/data status=200 ip=203.0.113.12
2025-08-20 12:45:00 REQUEST /api/data status=200 ip=203.0.113.12
... (100+ similar entries within 10 seconds)
2025-08-20 12:45:09 REQUEST /api/data status=200 ip=203.0.113.12
```

**Expected Output:**
```
🟡[MEDIUM ALERT] BLACKLISTED_IP: Access from blacklisted IP 203.0.113.12 by user unknown
🟣[CRITICAL ALERT] DOS_ATTACK: Possible DoS attack from 203.0.113.12 - 105 requests in 10 seconds
```

---

### 4.4 Sensitive File Access

**Sample Log Entries:**
```
2025-08-20 12:43:10 FILE_ACCESS path=/etc/passwd user=suspicious ip=192.168.1.100
2025-08-20 12:43:25 FILE_ACCESS path=/etc/shadow user=attacker ip=172.16.1.50
2025-08-20 12:43:40 FILE_ACCESS path=/root/.ssh/id_rsa user=hacker ip=10.0.0.5
```

**Expected Output:**
```
🟡[MEDIUM ALERT] BLACKLISTED_IP: Access from blacklisted IP 192.168.1.100 by user suspicious
🟡[MEDIUM ALERT] SENSITIVE_FILE_ACCESS: Access to sensitive file /etc/passwd from 192.168.1.100 by user suspicious
🟡[MEDIUM ALERT] BLACKLISTED_IP: Access from blacklisted IP 172.16.1.50 by user attacker
🟡[MEDIUM ALERT] SENSITIVE_FILE_ACCESS: Access to sensitive file /etc/shadow from 172.16.1.50 by user attacker
🟡[MEDIUM ALERT] BLACKLISTED_IP: Access from blacklisted IP 10.0.0.5 by user hacker
🟡[MEDIUM ALERT] SENSITIVE_FILE_ACCESS: Access to sensitive file /root/.ssh/id_rsa from 10.0.0.5 by user hacker
```

---

### 4.5 Blacklisted IP Access

**Sample Log Entries:**
```
2025-08-20 12:44:00 LOGIN SUCCESS user=admin ip=123.45.67.89
2025-08-20 12:44:15 REQUEST /admin status=200 ip=192.168.1.100
2025-08-20 12:44:30 QUERY "SELECT * FROM products" user=guest ip=203.0.113.12
```

**Expected Output:**
```
🟡[MEDIUM ALERT] BLACKLISTED_IP: Access from blacklisted IP 123.45.67.89 by user admin
🟡[MEDIUM ALERT] BLACKLISTED_IP: Access from blacklisted IP 192.168.1.100 by user unknown
🟡[MEDIUM ALERT] BLACKLISTED_IP: Access from blacklisted IP 203.0.113.12 by user guest
```

---

## 5. JSON Alerts Export

### File: `alerts.json`
```json
[
  {
    "timestamp": "2025-08-20T14:30:36.123456",
    "type": "BLACKLISTED_IP",
    "message": "Access from blacklisted IP 123.45.67.89 by user eve",
    "severity": "MEDIUM",
    "ip": "123.45.67.89",
    "user": "eve"
  },
  {
    "timestamp": "2025-08-20T14:30:37.234567",
    "type": "BRUTE_FORCE_ATTACK",
    "message": "Possible brute force attack from 123.45.67.89 - 5 failed attempts in 2 minutes",
    "severity": "HIGH",
    "ip": "123.45.67.89",
    "user": "admin",
    "attempts": 5
  },
  {
    "timestamp": "2025-08-20T14:30:39.345678",
    "type": "SQL_INJECTION",
    "message": "SQL injection attempt detected from 192.168.1.100 by user guest",
    "severity": "HIGH",
    "ip": "192.168.1.100",
    "user": "guest",
    "query": "SELECT * FROM users WHERE username='admin' OR '1'='1'"
  },
  {
    "timestamp": "2025-08-20T14:30:44.456789",
    "type": "DOS_ATTACK",
    "message": "Possible DoS attack from 203.0.113.12 - 102 requests in 10 seconds",
    "severity": "CRITICAL",
    "ip": "203.0.113.12",
    "requests": 102
  }
]
```

---

## 6. Error Handling Examples

### 6.1 File Not Found
**Command:** `python log_analyzer.py --logs nonexistent.log`
**Output:**
```
Analyzing log file: nonexistent.log
============================================================
Error: Log file nonexistent.log not found!
```

### 6.2 Malformed Log Lines
**Sample Log Entry:** `invalid log format without proper structure`
**Output:**
```
Error parsing line: invalid log format without proper structure... - time data 'invalid' does not match format '%Y-%m-%d %H:%M:%S'
```

---

## 7. Command Line Options

### Help Output
**Command:** `python log_analyzer.py --help`
**Output:**
```
usage: log_analyzer.py [-h] [--generate] [--logs LOGS] [--num-logs NUM_LOGS] [--report REPORT]

Cybersecurity Log Analyzer

optional arguments:
  -h, --help            show this help message and exit
  --generate, -g        Generate sample logs
  --logs LOGS, -l LOGS  Log file to analyze (default: sample_logs.log)
  --num-logs NUM_LOGS, -n NUM_LOGS
                        Number of sample logs to generate (default: 1000)
  --report REPORT, -r REPORT
                        Output report file (default: security_report.txt)
```

---

## 8. Color Coding Reference

- 🟢 **LOW**: Green - Informational alerts
- 🟡 **MEDIUM**: Yellow - Suspicious activities  
- 🔴 **HIGH**: Red - Confirmed threats
- 🟣 **CRITICAL**: Magenta - Severe security incidents

The analyzer provides real-time feedback, comprehensive reporting, and structured data export for integration with other security tools.

🏁 License

This project is licensed under the MIT License — feel free to use, modify, and share it with proper attribution.
