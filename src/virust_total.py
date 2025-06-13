import requests
import json
import time
from typing import Dict

from src.logger import logger


class VirusTotalChecker:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "PhishingDetector/1.0"})
        self.rate_limit_delay = 15  # 15 seconds between requests for free API
        self.last_request_time = 0

    def _wait_for_rate_limit(self):
        """Ensure we don't exceed VirusTotal rate limits"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time

        if time_since_last < self.rate_limit_delay:
            sleep_time = self.rate_limit_delay - time_since_last
            logger.info(f"Rate limiting: sleeping for {sleep_time:.1f} seconds")
            time.sleep(sleep_time)

        self.last_request_time = time.time()

    def check_domain_reputation(self, domain: str) -> Dict:
        """Check domain reputation using VirusTotal API"""
        self._wait_for_rate_limit()

        try:
            url = f"{self.base_url}/domain/report"
            params = {"apikey": self.api_key, "domain": domain}

            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()

            result = response.json()

            if result.get("response_code") == 1:
                return {
                    "found": True,
                    "positives": result.get("positives", 0),
                    "total": result.get("total", 0),
                    "scan_date": result.get("scan_date", ""),
                    "permalink": result.get("permalink", ""),
                    "scans": result.get("scans", {}),
                    "categories": result.get("categories", []),
                    "subdomains": result.get("subdomains", []),
                    "resolutions": result.get("resolutions", []),
                }
            else:
                return {
                    "found": False,
                    "message": result.get(
                        "verbose_msg", "Domain not found in VirusTotal"
                    ),
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal API error for domain {domain}: {e}")
            return {"found": False, "error": str(e)}
        except json.JSONDecodeError as e:
            logger.error(f"VirusTotal JSON decode error for domain {domain}: {e}")
            return {"found": False, "error": "Invalid JSON response"}
