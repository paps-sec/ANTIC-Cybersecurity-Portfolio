#!/usr/bin/env python3
"""
ANTIC Cameroon Apache Log Analyzer
Author: [Your Name]
Date: [Date]
"""

import re
import argparse
import pandas as pd
from collections import defaultdict
from datetime import datetime

# ANTIC Alert Thresholds
SUSPICIOUS_REQUESTS = 100  # Requests/min from single IP
ERROR_THRESHOLD = 50       # 4xx/5xx errors/min

def parse_log(file_path):
    """Parse Apache access logs with regex"""
    log_pattern = r'(\S+) (\S+) (\S+) \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) (\d+)'
    logs = []
    
    with open(file_path) as f:
        for line in f:
            match = re.match(log_pattern, line)
            if match:
                logs.append({
                    'ip': match.group(1),
                    'time': datetime.strptime(match.group(4), '%d/%b/%Y:%H:%M:%S %z'),
                    'method': match.group(5),
                    'endpoint': match.group(6),
                    'protocol': match.group(7),
                    'status': int(match.group(8)),
                    'bytes': int(match.group(9))
                })
    return logs

def analyze_logs(logs):
    """Identify suspicious patterns for ANTIC security teams"""
    analysis = {
        'ip_stats': defaultdict(int),
        'status_counts': defaultdict(int),
        'alerts': []
    }

    for log in logs:
        # Track requests per IP
        analysis['ip_stats'][log['ip']] += 1
        
        # Count HTTP status codes
        status_group = f"{log['status']}xx"
        analysis['status_counts'][status_group] += 1

    # Generate security alerts
    for ip, count in analysis['ip_stats'].items():
        if count > SUSPICIOUS_REQUESTS:
            analysis['alerts'].append(
                f"Suspicious activity from {ip}: {count} requests/minute"
            )

    error_count = sum(v for k,v in analysis['status_counts'].items() if k.startswith(('4','5')))
    if error_count > ERROR_THRESHOLD:
        analysis['alerts'].append(
            f"High error rate detected: {error_count} 4xx/5xx errors/minute"
        )

    return analysis

def generate_report(analysis, output_file):
    """Create ANTIC-compliant security report"""
    report = f"""# ANTIC Web Security Report
## Activity Summary ({datetime.now().strftime("%Y-%m-%d %H:%M")})

### Top IP Addresses
{pd.Series(analysis['ip_stats']).nlargest(5).to_markdown()}

### Status Code Distribution
{pd.Series(analysis['status_counts']).to_markdown()}

### Security Alerts
{"\n".join(f"- {alert}" for alert in analysis['alerts']) or "No critical alerts"}
"""
    
    with open(output_file, 'w') as f:
        f.write(report)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ANTIC Apache Log Analyzer")
    parser.add_argument("--log", required=True, help="Path to Apache access log")
    parser.add_argument("--output", default="antic_report.md", help="Output report file")
    args = parser.parse_args()

    logs = parse_log(args.log)
    analysis = analyze_logs(logs)
    generate_report(analysis, args.output)
    print(f"Generated ANTIC security report: {args.output}")