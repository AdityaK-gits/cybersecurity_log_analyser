#!/usr/bin/env python3
"""
Cybersecurity Log Analyzer
A Python tool that analyzes system/application logs to detect suspicious activities.
"""

import re
import json
import random
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Optional
import argparse
import os


class LogAnalyzer:
    """Main class for analyzing security logs and detecting threats."""
    
    def __init__(self):
        # Configuration
        self.blacklisted_ips = {
            "123.45.67.89", "192.168.1.100", "10.0.0.5", 
            "172.16.1.50", "203.0.113.12"
        }
        
        self.sql_injection_patterns = [
            r"'\s*or\s*'1'\s*=\s*'1'",
            r"union\s+select",
            r"drop\s+table",
            r"delete\s+from",
            r"insert\s+into",
            r"update\s+.*\s+set",
            r"--\s*",
            r"/\*.*\*/",
            r"xp_cmdshell",
            r"sp_executesql"
        ]
        
        # Tracking dictionaries
        self.failed_logins = defaultdict(list)
        self.request_counts = defaultdict(list)
        self.user_activities = defaultdict(list)
        self.file_access_attempts = defaultdict(list)
        
        # Alert storage
        self.alerts = []
        
        # Thresholds
        self.BRUTE_FORCE_THRESHOLD = 5
        self.BRUTE_FORCE_WINDOW = 2  # minutes
        self.DOS_THRESHOLD = 100
        self.DOS_WINDOW = 10  # seconds
        self.FILE_ACCESS_THRESHOLD = 20
        self.FILE_ACCESS_WINDOW = 5  # minutes

    def generate_sample_logs(self, filename: str = "sample_logs.log", num_logs: int = 1000):
        """Generate realistic sample logs for testing."""
        print(f"Generating {num_logs} sample log entries...")
        
        users = ["admin", "user1", "guest", "aditya", "john", "alice", "bob", "eve"]
        ips = [
            "192.168.1.10", "192.168.1.20", "10.0.0.1", "172.16.0.5",
            "203.0.113.1", "198.51.100.2", "123.45.67.89", "192.168.1.100"  # Some blacklisted
        ]
        
        actions = ["LOGIN", "LOGOUT", "FILE_ACCESS", "QUERY", "REQUEST"]
        files = ["/etc/passwd", "/var/log/auth.log", "/home/user/document.txt", 
                 "/root/.ssh/id_rsa", "/etc/shadow", "config.php"]
        
        start_time = datetime.now() - timedelta(hours=24)
        
        with open(filename, 'w') as f:
            for i in range(num_logs):
                timestamp = start_time + timedelta(seconds=random.randint(0, 86400))
                timestamp_str = timestamp.strftime("%Y-%m-%d %H:%M:%S")
                
                action = random.choice(actions)
                user = random.choice(users)
                ip = random.choice(ips)
                
                if action == "LOGIN":
                    # Simulate some failed logins for brute force detection
                    if random.random() < 0.2:  # 20% failure rate
                        status = "FAILED"
                        # Occasionally create brute force patterns
                        if random.random() < 0.1:
                            ip = "123.45.67.89"  # Blacklisted IP for brute force
                    else:
                        status = "SUCCESS"
                    
                    log_entry = f"{timestamp_str} LOGIN {status} user={user} ip={ip}\n"
                
                elif action == "QUERY":
                    # Occasionally inject SQL injection attempts
                    if random.random() < 0.05:  # 5% malicious queries
                        queries = [
                            "SELECT * FROM users WHERE username='admin' OR '1'='1'",
                            "SELECT * FROM accounts UNION SELECT password FROM admin",
                            "DROP TABLE users; --",
                            "UPDATE users SET password='hacked' WHERE 1=1"
                        ]
                        query = random.choice(queries)
                    else:
                        query = f"SELECT * FROM users WHERE id={random.randint(1,100)}"
                    
                    log_entry = f'{timestamp_str} QUERY "{query}" user={user} ip={ip}\n'
                
                elif action == "FILE_ACCESS":
                    file_path = random.choice(files)
                    # Simulate suspicious file access
                    if random.random() < 0.1:  # 10% suspicious access
                        file_path = "/etc/passwd"
                        ip = "192.168.1.100"  # Blacklisted IP
                    
                    log_entry = f"{timestamp_str} FILE_ACCESS path={file_path} user={user} ip={ip}\n"
                
                elif action == "REQUEST":
                    endpoint = random.choice(["/api/data", "/login", "/admin", "/upload"])
                    status_code = random.choices([200, 404, 500, 403], weights=[70, 15, 10, 5])[0]
                    
                    # Simulate DoS patterns
                    if random.random() < 0.02:  # 2% DoS attempts
                        ip = "203.0.113.12"  # Use blacklisted IP for DoS
                    
                    log_entry = f"{timestamp_str} REQUEST {endpoint} status={status_code} ip={ip}\n"
                
                else:
                    log_entry = f"{timestamp_str} LOGOUT user={user} ip={ip}\n"
                
                f.write(log_entry)
        
        print(f"Sample logs generated successfully: {filename}")

    def parse_log_line(self, line: str) -> Optional[Dict]:
        """Parse a single log line and extract relevant information."""
        line = line.strip()
        if not line:
            return None
        
        try:
            # 1. Extract timestamp
            timestamp_match = re.match(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
            if not timestamp_match:
                # If the line doesn't start with the expected timestamp format, skip it
                return None
            
            timestamp_str = timestamp_match.group(1)
            timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
            
            # 2. Extract IP (made more robust)
            ip_match = re.search(r"ip=(\S+)|(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            # If 'ip=' tag is present, use it; otherwise, try to find any bare IP address
            ip = ip_match.group(1) or ip_match.group(2) if ip_match else "unknown"
            
            # 3. Extract user (made more robust)
            user_match = re.search(r"user=(\S+)", line)
            user = user_match.group(1) if user_match else "guest" # Default to 'guest' if no user found
            
            # Determine log type and extract specific data
            log_data = {
                "timestamp": timestamp,
                "ip": ip.strip(","), # Clean up possible trailing comma/chars
                "user": user.strip(","),
                "raw": line
            }
            
            # The rest of the parsing logic remains the same and is solid for the generated format
            if "LOGIN FAILED" in line:
                log_data["type"] = "login_failed"
            elif "LOGIN SUCCESS" in line:
                log_data["type"] = "login_success"
            elif "QUERY" in line:
                log_data["type"] = "query"
                query_match = re.search(r'QUERY "([^"]*)"', line)
                log_data["query"] = query_match.group(1) if query_match else ""
            elif "FILE_ACCESS" in line:
                log_data["type"] = "file_access"
                path_match = re.search(r"path=(\S+)", line)
                log_data["path"] = path_match.group(1) if path_match else ""
            elif "REQUEST" in line:
                log_data["type"] = "request"
                endpoint_match = re.search(r"REQUEST (\S+)", line)
                log_data["endpoint"] = endpoint_match.group(1) if endpoint_match else ""
            else:
                # Catch-all for other log types like LOGOUT or unparsed lines
                log_data["type"] = "other" 
            
            return log_data
        
        except Exception as e:
            # This is important for debugging issues with user-uploaded files
            print(f"Error parsing line: {line[:50]}... - {e}")
            return None

    # ... (All other detection methods like detect_brute_force, detect_sql_injection, etc., remain the same)
    
    # NOTE: You can remove the rest of the class methods here for brevity, 
    # as they were not changed and are already correct, but they MUST remain in your actual file.


    def add_alert(self, alert_type: str, message: str, severity: str = "MEDIUM", **kwargs):
        """Add an alert to the alerts list."""
        alert = {
            "timestamp": datetime.now(),
            "type": alert_type,
            "message": message,
            "severity": severity,
            **kwargs
        }
        self.alerts.append(alert)
        
        # Print alert immediately
        severity_color = {
            "LOW": "\033[92m",      # Green
            "MEDIUM": "\033[93m",   # Yellow  
            "HIGH": "\033[91m",     # Red
            "CRITICAL": "\033[95m"  # Magenta
        }
        
        color = severity_color.get(severity, "\033[0m")
        print(f"{color}[{severity} ALERT] {alert_type}: {message}\033[0m")


    def detect_brute_force(self, log_data: Dict):
        """Detect brute force attacks based on failed login attempts."""
        if log_data["type"] != "login_failed":
            return
        
        ip = log_data["ip"]
        timestamp = log_data["timestamp"]
        
        # Add failed attempt
        self.failed_logins[ip].append(timestamp)
        
        # Clean old attempts outside the window
        cutoff_time = timestamp - timedelta(minutes=self.BRUTE_FORCE_WINDOW)
        self.failed_logins[ip] = [t for t in self.failed_logins[ip] if t > cutoff_time]
        
        # Check threshold
        if len(self.failed_logins[ip]) >= self.BRUTE_FORCE_THRESHOLD:
            self.add_alert(
                "BRUTE_FORCE_ATTACK",
                f"Possible brute force attack from {ip} - {len(self.failed_logins[ip])} failed attempts in {self.BRUTE_FORCE_WINDOW} minutes",
                "HIGH",
                ip=ip,
                user=log_data["user"],
                attempts=len(self.failed_logins[ip])
            )

    def detect_sql_injection(self, log_data: Dict):
        """Detect SQL injection attempts in queries."""
        if log_data["type"] != "query" or not log_data.get("query"):
            return
        
        query = log_data["query"].lower()
        
        for pattern in self.sql_injection_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                self.add_alert(
                    "SQL_INJECTION",
                    f"SQL injection attempt detected from {log_data['ip']} by user {log_data['user']}",
                    "HIGH",
                    ip=log_data["ip"],
                    user=log_data["user"],
                    query=log_data["query"]
                )
                break

    def detect_blacklisted_ip(self, log_data: Dict):
        """Detect access from blacklisted IPs."""
        if log_data["ip"] in self.blacklisted_ips:
            self.add_alert(
                "BLACKLISTED_IP",
                f"Access from blacklisted IP {log_data['ip']} by user {log_data['user']}",
                "MEDIUM",
                ip=log_data["ip"],
                user=log_data["user"]
            )

    def detect_suspicious_file_access(self, log_data: Dict):
        """Detect suspicious file access patterns."""
        if log_data["type"] != "file_access":
            return
        
        sensitive_files = ["/etc/passwd", "/etc/shadow", "/root/.ssh/id_rsa", "/var/log/auth.log"]
        
        if log_data.get("path") in sensitive_files:
            ip = log_data["ip"]
            timestamp = log_data["timestamp"]
            
            # Track access attempts
            self.file_access_attempts[ip].append(timestamp)
            
            # Clean old attempts
            cutoff_time = timestamp - timedelta(minutes=self.FILE_ACCESS_WINDOW)
            self.file_access_attempts[ip] = [t for t in self.file_access_attempts[ip] if t > cutoff_time]
            
            # Alert on sensitive file access
            self.add_alert(
                "SENSITIVE_FILE_ACCESS",
                f"Access to sensitive file {log_data['path']} from {ip} by user {log_data['user']}",
                "MEDIUM",
                ip=ip,
                user=log_data["user"],
                path=log_data["path"]
            )
            
            # Check for excessive access
            if len(self.file_access_attempts[ip]) >= self.FILE_ACCESS_THRESHOLD:
                self.add_alert(
                    "EXCESSIVE_FILE_ACCESS",
                    f"Excessive file access from {ip} - {len(self.file_access_attempts[ip])} attempts in {self.FILE_ACCESS_WINDOW} minutes",
                    "HIGH",
                    ip=ip,
                    attempts=len(self.file_access_attempts[ip])
                )

    def detect_dos_attack(self, log_data: Dict):
        """Detect denial of service attacks based on request frequency."""
        if log_data["type"] != "request":
            return
        
        ip = log_data["ip"]
        timestamp = log_data["timestamp"]
        
        # Track requests
        self.request_counts[ip].append(timestamp)
        
        # Clean old requests outside window
        cutoff_time = timestamp - timedelta(seconds=self.DOS_WINDOW)
        self.request_counts[ip] = [t for t in self.request_counts[ip] if t > cutoff_time]
        
        # Check threshold
        if len(self.request_counts[ip]) >= self.DOS_THRESHOLD:
            self.add_alert(
                "DOS_ATTACK",
                f"Possible DoS attack from {ip} - {len(self.request_counts[ip])} requests in {self.DOS_WINDOW} seconds",
                "CRITICAL",
                ip=ip,
                requests=len(self.request_counts[ip])
            )

    def analyze_logs(self, log_file: str):
        """Main method to analyze log file."""
        print(f"Analyzing log file: {log_file}")
        print("=" * 60)
        
        if not os.path.exists(log_file):
            print(f"Error: Log file {log_file} not found!")
            return
        
        total_lines = 0
        processed_lines = 0
        
        with open(log_file, 'r') as f:
            for line in f:
                total_lines += 1
                log_data = self.parse_log_line(line)
                
                if log_data:
                    processed_lines += 1
                    
                    # Run all detection methods
                    self.detect_blacklisted_ip(log_data)
                    self.detect_brute_force(log_data)
                    self.detect_sql_injection(log_data)
                    self.detect_suspicious_file_access(log_data)
                    self.detect_dos_attack(log_data)
        
        print(f"\nProcessed {processed_lines}/{total_lines} log entries")
        print(f"Total alerts generated: {len(self.alerts)}")

    def generate_report(self, output_file: str = "security_report.txt"):
        """Generate a comprehensive security report."""
        print(f"\nGenerating security report: {output_file}")
        
        with open(output_file, 'w') as f:
            f.write("CYBERSECURITY LOG ANALYSIS REPORT\n")
            f.write("=" * 50 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Alert summary
            alert_counts = Counter(alert["type"] for alert in self.alerts)
            severity_counts = Counter(alert["severity"] for alert in self.alerts)
            
            f.write("ALERT SUMMARY\n")
            f.write("-" * 20 + "\n")
            for alert_type, count in alert_counts.most_common():
                f.write(f"{alert_type}: {count}\n")
            
            f.write("\nSEVERITY BREAKDOWN\n")
            f.write("-" * 20 + "\n")
            for severity, count in severity_counts.most_common():
                f.write(f"{severity}: {count}\n")
            
            # Detailed alerts
            f.write("\nDETAILED ALERTS\n")
            f.write("-" * 20 + "\n")
            for alert in sorted(self.alerts, key=lambda x: x["timestamp"], reverse=True):
                f.write(f"[{alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}] ")
                f.write(f"{alert['severity']} - {alert['type']}: {alert['message']}\n")
            
            # Top suspicious IPs
            suspicious_ips = Counter()
            for alert in self.alerts:
                if "ip" in alert:
                    suspicious_ips[alert["ip"]] += 1
            
            if suspicious_ips:
                f.write("\nTOP SUSPICIOUS IPs\n")
                f.write("-" * 20 + "\n")
                for ip, count in suspicious_ips.most_common(10):
                    f.write(f"{ip}: {count} alerts\n")
        
        print(f"Report saved to: {output_file}")

    def save_alerts(self, output_file: str = "alerts.json"):
        """Save alerts to JSON file for further processing."""
        alerts_data = []
        for alert in self.alerts:
            alert_copy = alert.copy()
            alert_copy["timestamp"] = alert_copy["timestamp"].isoformat()
            alerts_data.append(alert_copy)
        
        with open(output_file, 'w') as f:
            json.dump(alerts_data, f, indent=2)
        
        print(f"Alerts saved to: {output_file}")


def main():
    """Main function to run the log analyzer."""
    parser = argparse.ArgumentParser(description="Cybersecurity Log Analyzer")
    parser.add_argument("--generate", "-g", action="store_true", 
                        help="Generate sample logs")
    parser.add_argument("--logs", "-l", default="sample_logs.log",
                        help="Log file to analyze (default: sample_logs.log)")
    parser.add_argument("--num-logs", "-n", type=int, default=1000,
                        help="Number of sample logs to generate (default: 1000)")
    parser.add_argument("--report", "-r", default="security_report.txt",
                        help="Output report file (default: security_report.txt)")
    
    args = parser.parse_args()
    
    # Create analyzer instance
    analyzer = LogAnalyzer()
    
    # Generate sample logs if requested
    if args.generate:
        analyzer.generate_sample_logs(args.logs, args.num_logs)
    
    # Analyze logs
    if os.path.exists(args.logs):
        analyzer.analyze_logs(args.logs)
        
        # Generate reports
        analyzer.generate_report(args.report)
        analyzer.save_alerts("alerts.json")
        
        # --- NEW: Cleanup for uploaded files ---
        # The 'uploaded_logs.log' file is temporary and should be removed after analysis
        if args.logs == "uploaded_logs.log":
            try:
                os.remove(args.logs)
                print(f"\nCleanup: Removed temporary file {args.logs}")
            except OSError as e:
                print(f"\nCleanup Warning: Could not remove temporary file {args.logs}: {e}")
        # --------------------------------------
        
        print(f"\n🔒 Analysis complete! Check {args.report} for detailed findings.")
    else:
        print(f"Log file {args.logs} not found. Use --generate to create sample logs.")


if __name__ == "__main__":
    main()
