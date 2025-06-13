import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.logger import logger
from src.phishing import PhishingDetector


def parse_args():
    import argparse

    parser = argparse.ArgumentParser(
        description="Enhanced CT Log Phishing Detection Tool"
    )
    parser.add_argument(
        "--monitor", action="store_true", help="Run continuous monitoring"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=300,
        help="Monitoring interval in seconds (default: 300)",
    )
    parser.add_argument(
        "--single", action="store_true", help="Run single enhanced scan"
    )
    parser.add_argument("--vt-api-key", type=str, help="VirusTotal API key")
    parser.add_argument("--gsb-api-key", type=str, help="Google Safe Browsing API key")

    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = parse_args()

    vt_api_key = args.vt_api_key or os.getenv("VIRUSTOTAL_API_KEY")
    gsb_api_key = args.gsb_api_key or os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

    if not vt_api_key:
        logger.warning("No VirusTotal API key provided.")
    if not gsb_api_key:
        logger.warning("No Google Safe Browsing API key provided.")

    detector = PhishingDetector(vt_api_key=vt_api_key, gsb_api_key=gsb_api_key)

    if args.monitor:
        detector.monitor_certificates_enhanced(args.interval)
    else:
        detector.run_enhanced_scan()
