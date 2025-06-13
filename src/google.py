import requests
from typing import Dict

from src.logger import logger


class GoogleSafeBrowsingChecker:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        self.session = requests.Session()

    def check_url(self, url: str) -> Dict:
        """Check URL against Google Safe Browsing"""
        if not self.api_key:
            return {"found": False, "error": "No API key provided"}

        payload = {
            "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        try:
            response = self.session.post(
                f"{self.base_url}?key={self.api_key}", json=payload, timeout=30
            )
            result = response.json()

            return {
                "found": "matches" in result,
                "threats": result.get("matches", []),
                "threat_types": [
                    match.get("threatType") for match in result.get("matches", [])
                ],
            }
        except Exception as e:
            logger.error(f"Google Safe Browsing error: {e}")
            return {"found": False, "error": str(e)}
