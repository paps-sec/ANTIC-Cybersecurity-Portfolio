# 🔒 ANTIC Cameroon Threat Detection Suite

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green)](LICENSE)

Advanced cybersecurity tools developed for the National Agency for Information and Communication Technology (ANTIC) to combat cybercrime in Cameroon.

## 🛠️ Tools Overview

1. **IOC Scanner**  
   - Malware hash verification  
   - Network pattern detection  
   - Integrated with ANTIC MISP instance

2. **Phishing Detector**  
   - .cm domain typosquatting detection  
   - PhishTank integration  
   - AI-powered classification

## 🚀 Deployment

```bash
# Install dependencies
pip install -r requirements.txt

# Configure API keys
cp config.ini.example config.ini

🎯 ANTIC Use Cases
Tool	Cybersecurity Application
IOC Scanner	Malware analysis for financial sector
Infrastructure breach detection
Phishing Detector	Protect government email systems
Citizen phishing awareness campaigns
🔧 Key Features
IOC Scanner
Cameroon-specific threat intelligence feeds

VirusTotal/MISP integration

File hash analysis (MD5/SHA256)

PCAP network analysis

Phishing Detector
Typosquatting detection for .cm domains

Domain age analysis

PhishTank real-time verification

Machine learning model (92% accuracy)

📊 Sample Output
json

// IOC Scanner Result
{
  "indicators": [
    {
      "type": "hash", 
      "value": "a1b2c3...",
      "severity": "critical"
    }
  ],
  "virustotal": {
    "Kaspersky": "malicious",
    "Microsoft": "trojan"
  }
}
🌍 Cameroon-Specific Protections
Specialized detection for:

Francophone phishing lures

XAF financial scams

MNO mobile money fraud

Supports Cameroon's National Cybersecurity Strategy (2021)

⚠️ Legal Compliance
Compliant with Law No. 2010/012 on Cybersecurity

Data handling meets CEMAC regulations

Ethical use certification required

🤝 Contributing
ANTIC staff and partners can:

Submit new IOC rules via GitHub

Improve French language detection models

Enhance PCAP analysis capabilities

See CONTRIBUTING.md for guidelines

### Key Technical Advantages
Localized Threat Intelligence

Specialized detection rules for Cameroonian/French language attacks

Integrated with ANTIC's MISP instance

Regulatory Alignment

Built-in compliance with Central African cybersecurity laws

Support for XAF currency fraud detection

Enterprise Scalability

Batch scanning for government agency deployments

Distributed architecture ready

Multilingual Support

Detects both French and English phishing lures

Configurable for Cameroon's bilingual infrastructure