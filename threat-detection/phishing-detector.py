#!/usr/bin/env python3
"""
ANTIC Cameroon Phishing Detection System
Author: Bertrand Fossung
Date: 26-02-2025
"""

import re
import tldextract
import whois
import requests
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from urllib.parse import urlparse

class ANTICPhishingDetector:
    def __init__(self):
        self.model = self._load_model()
        self.phishtank_api = "https://checkurl.phishtank.com/checkurl/"
        
    def _load_model(self):
        """Load pre-trained model for Cameroonian domains"""
        return RandomForestClassifier()  # Pretend-load from phishing_model.pkl

    def _extract_features(self, url: str) -> Dict:
        """Feature engineering for .cm domains"""
        parsed = urlparse(url)
        domain_info = tldextract.extract(url)
        
        features = {
            'domain_age_days': self._get_domain_age(domain_info.registered_domain),
            'num_subdomains': len(domain_info.subdomain.split('.')),
            'https': int(parsed.scheme == 'https'),
            'num_redirects': self._count_redirects(url),
            'special_chars': len(re.findall(r'[^\w\.-]', url)),
            'is_typosquat': self._check_typosquatting(domain_info.registered_domain)
        }
        return features

    def _get_domain_age(self, domain: str) -> int:
        """Check WHOIS for .cm domain registration"""
        try:
            info = whois.whois(domain)
            if info.creation_date:
                age = (datetime.now() - info.creation_date[0]).days
                return age if age > 0 else 0
        except:
            return 0

    def _check_typosquatting(self, domain: str) -> int:
        """Detect common Cameroon government typos"""
        legit_domains = ["gouv.cm", "antic.cm", "minpostel.cm"]
        return any(1 for ld in legit_domains if self._levenshtein(domain, ld) <= 2)

    def check_phishtank(self, url: str) -> bool:
        """Verify against PhishTank database"""
        response = requests.post(
            self.phishtank_api,
            data={'url': url, 'format': 'json'},
            timeout=5
        )
        return response.json().get('results', {}).get('in_database', False)

    def predict(self, url: str) -> float:
        """Predict phishing probability (0-1)"""
        features = pd.DataFrame([self._extract_features(url)])
        return self.model.predict_proba(features)[0][1]

if __name__ == "__main__":
    detector = ANTICPhishingDetector()
    test_url = "http://g0uv.cm-login.secure.verify"
    
    print(f"Analyzing {test_url}")
    print(f"PhishTank Match: {detector.check_phishtank(test_url)}")
    print(f"AI Prediction: {detector.predict(test_url):.2%} probability")