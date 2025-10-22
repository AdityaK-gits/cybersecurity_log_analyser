


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
<img width="927" height="530" alt="Screenshot 2025-10-22 200417" src="https://github.com/user-attachments/assets/c9eea0d9-5598-4266-88f0-d37bc7726c94" />
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

🏁 License

This project is licensed under the MIT License — feel free to use, modify, and share it with proper attribution.
