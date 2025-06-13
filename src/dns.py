import json
import subprocess
from typing import List, Dict

from src.logger import logger


class DNSTwistChecker:
    def __init__(self):
        self.dnstwist_available = self._check_dnstwist_availability()

    def _check_dnstwist_availability(self) -> bool:
        """Check if dnstwist is available"""
        try:
            subprocess.run(["dnstwist", "--help"], capture_output=True, timeout=10)
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning("dnstwist not found. Install with: pip install dnstwist")
            return False

    def generate_typosquatting_domains(self, domain: str) -> List[Dict]:
        """Generate typosquatting variants using dnstwist"""
        if not self.dnstwist_available:
            return []

        try:
            cmd = ["dnstwist", "--format", "json", "--registered", domain]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode == 0:
                variants = json.loads(result.stdout)
                return [v for v in variants if v.get("domain") != domain]
            return []
        except Exception as e:
            logger.error(f"DNSTwist error for {domain}: {e}")
            return []
