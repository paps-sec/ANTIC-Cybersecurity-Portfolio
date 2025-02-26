#!/usr/bin/env python3
"""
ANTIC Cameroon SIEM Integration Tool
Author: [Your Name]
Date: [Date]
"""

import json
import requests
import logging
from datetime import datetime

class ANTICSIEM:
    def __init__(self, siem_type, config):
        self.siem_type = siem_type
        self.config = config
        self.logger = logging.getLogger("ANTIC-SIEM")
        
    def send_to_siem(self, logs):
        """Forward logs to configured SIEM"""
        try:
            if self.siem_type == "elasticsearch":
                return self._send_to_elasticsearch(logs)
            elif self.siem_type == "splunk":
                return self._send_to_splunk(logs)
            else:
                raise ValueError("Unsupported SIEM type")
        except Exception as e:
            self.logger.error(f"SIEM integration failed: {str(e)}")
            return False

    def _send_to_elasticsearch(self, logs):
        """Send logs to Elasticsearch"""
        headers = {"Content-Type": "application/json"}
        url = f"{self.config['host']}/antic-logs-{datetime.now().strftime('%Y.%m')}/_doc"
        
        response = requests.post(
            url,
            auth=(self.config['user'], self.config['password']),
            headers=headers,
            json=logs,
            timeout=10
        )
        response.raise_for_status()
        return True

    def _send_to_splunk(self, logs):
        """Send logs to Splunk HEC"""
        headers = {
            "Authorization": f"Splunk {self.config['token']}",
            "Content-Type": "application/json"
        }
        
        payload = {
            "event": logs,
            "sourcetype": "_json",
            "index": self.config['index']
        }
        
        response = requests.post(
            self.config['hec_url'],
            headers=headers,
            json=payload,
            timeout=10
        )
        response.raise_for_status()
        return True

if __name__ == "__main__":
    # Example usage
    import configparser
    
    config = configparser.ConfigParser()
    config.read('siem_config.ini')
    
    siem = ANTICSIEM(
        siem_type="elasticsearch",
        config=config['ELASTICSEARCH']
    )
    
    sample_logs = [{
        "timestamp": datetime.now().isoformat(),
        "ip": "196.200.1.1",
        "status": 403,
        "alert": "Potential brute force attempt"
    }]
    
    if siem.send_to_siem(sample_logs):
        print("Logs successfully sent to ANTIC SIEM")