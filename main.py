import requests
import json
import time
import sqlite3
import re
import os
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('phishing_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class VirusTotalChecker:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/vtapi/v2"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'PhishingDetector/1.0'
        })
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
            params = {
                'apikey': self.api_key,
                'domain': domain
            }

            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()

            result = response.json()

            print(f"{result = }")

            if result.get('response_code') == 1:
                return {
                    'found': True,
                    'positives': result.get('positives', 0),
                    'total': result.get('total', 0),
                    'scan_date': result.get('scan_date', ''),
                    'permalink': result.get('permalink', ''),
                    'scans': result.get('scans', {}),
                    'categories': result.get('categories', []),
                    'subdomains': result.get('subdomains', []),
                    'resolutions': result.get('resolutions', [])
                }
            else:
                return {
                    'found': False,
                    'message': result.get('verbose_msg', 'Domain not found in VirusTotal')
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal API error for domain {domain}: {e}")
            return {'found': False, 'error': str(e)}
        except json.JSONDecodeError as e:
            logger.error(f"VirusTotal JSON decode error for domain {domain}: {e}")
            return {'found': False, 'error': 'Invalid JSON response'}

    def check_url_reputation(self, url: str) -> Dict:
        """Check URL reputation using VirusTotal API"""
        self._wait_for_rate_limit()

        try:
            # First check if URL exists in database
            check_url = f"{self.base_url}/url/report"
            params = {
                'apikey': self.api_key,
                'resource': url
            }

            response = self.session.post(check_url, data=params, timeout=30)
            response.raise_for_status()

            result = response.json()

            if result.get('response_code') == 1:
                return {
                    'found': True,
                    'positives': result.get('positives', 0),
                    'total': result.get('total', 0),
                    'scan_date': result.get('scan_date', ''),
                    'permalink': result.get('permalink', ''),
                    'scans': result.get('scans', {})
                }
            else:
                return {
                    'found': False,
                    'message': result.get('verbose_msg', 'URL not found in VirusTotal')
                }

        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal API error for URL {url}: {e}")
            return {'found': False, 'error': str(e)}
        except json.JSONDecodeError as e:
            logger.error(f"VirusTotal JSON decode error for URL {url}: {e}")
            return {'found': False, 'error': 'Invalid JSON response'}

class PhishingDetector:
    def __init__(self, db_path: str = "phishing_monitor.db", vt_api_key: str = None):
        self.db_path = db_path
        self.vt_checker = VirusTotalChecker(vt_api_key) if vt_api_key else None
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'PhishingDetector/1.0'
        })

        # Target brands/services to monitor
        self.target_keywords = [
            'paypal', 'amazon', 'google',
            # TODO commented out for testing
            # 'microsoft', 'apple', 'facebook',
            # 'instagram', 'twitter', 'linkedin', 'netflix', 'spotify',
            # 'bankofamerica', 'chase', 'wellsfargo', 'citibank',
            # 'societegenerale', 'bnpparibas', 'creditagricole',
            # 'gmail', 'outlook', 'yahoo', 'dropbox', 'github'
        ]

        # Suspicious patterns
        self.suspicious_patterns = [
            r'.*-[a-z0-9]{8,}\..*',  # Random suffix
            r'.*[0-9]{4,}\..*',      # Multiple digits
            r'.*-?(secure|verify|update|login|account).*',  # Phishing keywords
            r'.*\.(tk|ml|ga|cf)$',   # Suspicious TLDs
        ]

        self.init_database()

    def init_database(self):
        """Initialize SQLite database for tracking processed certificates"""
        # Check if database exists and has correct schema
        needs_recreation = False

        if os.path.exists(self.db_path):
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()

                # Check if tables exist with correct schema
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='processed_certs'")
                if not cursor.fetchone():
                    needs_recreation = True
                else:
                    # Check if cert_id column exists
                    cursor.execute("PRAGMA table_info(processed_certs)")
                    columns = [column[1] for column in cursor.fetchall()]
                    if 'cert_id' not in columns:
                        needs_recreation = True

                conn.close()
            except sqlite3.Error as e:
                logger.warning(f"Database error during schema check: {e}")
                needs_recreation = True
        else:
            needs_recreation = True

        if needs_recreation:
            # Remove old database if it exists
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
                logger.info("Removed old database with incorrect schema")

            # Create new database with correct schema
            self._create_database()
        else:
            logger.info("Database schema is correct")

    def _create_database(self):
        """Create database with proper schema including VirusTotal data"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Drop tables if they exist (for clean recreation)
        cursor.execute('DROP TABLE IF EXISTS processed_certs')
        cursor.execute('DROP TABLE IF EXISTS phishing_alerts')
        cursor.execute('DROP TABLE IF EXISTS virustotal_checks')

        # Create processed_certs table
        cursor.execute('''
            CREATE TABLE processed_certs (
                cert_id INTEGER PRIMARY KEY,
                domain TEXT NOT NULL,
                issuer TEXT,
                timestamp TEXT,
                is_suspicious INTEGER DEFAULT 0,
                keywords_matched TEXT,
                processed_at TEXT NOT NULL
            )
        ''')

        # Create phishing_alerts table
        cursor.execute('''
            CREATE TABLE phishing_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                cert_id INTEGER,
                risk_score INTEGER NOT NULL,
                matched_keywords TEXT,
                suspicious_patterns TEXT,
                detected_at TEXT NOT NULL,
                vt_positives INTEGER DEFAULT 0,
                vt_total INTEGER DEFAULT 0,
                vt_checked INTEGER DEFAULT 0,
                status TEXT DEFAULT 'new',
                FOREIGN KEY (cert_id) REFERENCES processed_certs (cert_id)
            )
        ''')

        # Create VirusTotal checks table
        cursor.execute('''
            CREATE TABLE virustotal_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                check_type TEXT NOT NULL,
                vt_found INTEGER DEFAULT 0,
                vt_positives INTEGER DEFAULT 0,
                vt_total INTEGER DEFAULT 0,
                vt_scan_date TEXT,
                vt_permalink TEXT,
                vt_categories TEXT,
                checked_at TEXT NOT NULL,
                UNIQUE(domain, check_type)
            )
        ''')

        # Create indexes for better performance
        cursor.execute('CREATE INDEX idx_processed_certs_cert_id ON processed_certs(cert_id)')
        cursor.execute('CREATE INDEX idx_processed_certs_domain ON processed_certs(domain)')
        cursor.execute('CREATE INDEX idx_phishing_alerts_detected_at ON phishing_alerts(detected_at)')
        cursor.execute('CREATE INDEX idx_phishing_alerts_risk_score ON phishing_alerts(risk_score)')
        cursor.execute('CREATE INDEX idx_virustotal_checks_domain ON virustotal_checks(domain)')

        conn.commit()
        conn.close()
        logger.info("Database created successfully with VirusTotal integration")

    def query_crtsh(self, domain_pattern: str = None, limit: int = 1000) -> List[Dict]:
        """Query crt.sh API for certificates"""
        try:
            if domain_pattern:
                url = f"https://crt.sh/?q={domain_pattern}&output=json"
            else:
                # Get recent certificates (last 24 hours simulation)
                url = f"https://crt.sh/?output=json"

            response = self.session.get(url, timeout=30)
            response.raise_for_status()

            if response.text.strip():
                certs = json.loads(response.text)
                # Sort by entry timestamp and limit results
                if isinstance(certs, list):
                    certs.sort(key=lambda x: x.get('entry_timestamp', ''), reverse=True)
                    return certs[:limit]
                return []
            return []

        except requests.exceptions.RequestException as e:
            logger.error(f"Error querying crt.sh: {e}")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON response: {e}")
            return []

    def get_recent_certs_by_keywords(self) -> List[Dict]:
        """Get recent certificates containing target keywords"""
        all_certs = []

        for keyword in self.target_keywords:
            logger.info(f"Searching for certificates containing '{keyword}'")

            # Search with wildcard
            pattern = f"%.{keyword}.%"

            # TODO make virus total optional and use less limit for it
            # certs = self.query_crtsh(pattern, limit=10)
            # for virust toal testing
            certs = self.query_crtsh(pattern, limit=1)

            if certs:
                logger.info(f"Found {len(certs)} certificates for keyword '{keyword}'")
                all_certs.extend(certs)

            # Add delay to avoid rate limiting
            time.sleep(1)

        # Remove duplicates based on cert ID
        unique_certs = {}
        for cert in all_certs:
            cert_id = cert.get('id')
            if cert_id and cert_id not in unique_certs:
                unique_certs[cert_id] = cert

        return list(unique_certs.values())

    def is_cert_processed(self, cert_id: int) -> bool:
        """Check if certificate has already been processed"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("SELECT 1 FROM processed_certs WHERE cert_id = ?", (cert_id,))
            result = cursor.fetchone() is not None

            conn.close()
            return result
        except sqlite3.Error as e:
            logger.error(f"Database error in is_cert_processed: {e}")
            return False

    def check_virustotal_cache(self, domain: str) -> Optional[Dict]:
        """Check if domain has been checked with VirusTotal recently"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Check if domain was checked in last 24 hours
            since = (datetime.now() - timedelta(hours=24)).isoformat()

            cursor.execute('''
                SELECT vt_found, vt_positives, vt_total, vt_scan_date, vt_permalink, vt_categories
                FROM virustotal_checks 
                WHERE domain = ? AND check_type = 'domain' AND checked_at > ?
            ''', (domain, since))

            result = cursor.fetchone()
            conn.close()

            if result:
                return {
                    'found': bool(result[0]),
                    'positives': result[1] or 0,
                    'total': result[2] or 0,
                    'scan_date': result[3] or '',
                    'permalink': result[4] or '',
                    'categories': result[5] or '',
                    'cached': True
                }
            return None
        except sqlite3.Error as e:
            logger.error(f"Database error in check_virustotal_cache: {e}")
            return None

    def save_virustotal_result(self, domain: str, vt_result: Dict):
        """Save VirusTotal check result to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute('''
                INSERT OR REPLACE INTO virustotal_checks 
                (domain, check_type, vt_found, vt_positives, vt_total, vt_scan_date, 
                 vt_permalink, vt_categories, checked_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                domain,
                'domain',
                1 if vt_result.get('found', False) else 0,
                vt_result.get('positives', 0),
                vt_result.get('total', 0),
                vt_result.get('scan_date', ''),
                vt_result.get('permalink', ''),
                ','.join(vt_result.get('categories', [])) if vt_result.get('categories') else '',
                datetime.now().isoformat()
            ))

            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"Database error in save_virustotal_result: {e}")

    def check_with_virustotal(self, domain: str) -> Dict:
        """Check domain with VirusTotal (with caching)"""
        if not self.vt_checker:
            return {'found': False, 'error': 'VirusTotal API key not provided'}

        # Check cache first
        cached_result = self.check_virustotal_cache(domain)
        if cached_result:
            logger.info(f"Using cached VirusTotal result for {domain}")
            return cached_result

        # Query VirusTotal API
        logger.info(f"Checking {domain} with VirusTotal API")
        vt_result = self.vt_checker.check_domain_reputation(domain)

        # Save result to cache
        self.save_virustotal_result(domain, vt_result)

        return vt_result

    def calculate_risk_score(self, domain: str, matched_keywords: List[str], vt_result: Dict = None) -> int:
        """Calculate risk score for a domain including VirusTotal data"""
        score = 0

        # Base score for keyword matches
        score += len(matched_keywords) * 10

        # Check for suspicious patterns
        for pattern in self.suspicious_patterns:
            if re.match(pattern, domain.lower()):
                score += 20

        # Check for typosquatting indicators
        if self.has_typosquatting_indicators(domain):
            score += 30

        # Domain length (very long domains are suspicious)
        if len(domain) > 50:
            score += 15

        # Multiple subdomains
        subdomain_count = domain.count('.')
        if subdomain_count > 3:
            score += 10

        # VirusTotal integration
        if vt_result and vt_result.get('found'):
            positives = vt_result.get('positives', 0)
            total = vt_result.get('total', 0)

            if total > 0:
                detection_ratio = positives / total

                # High detection ratio significantly increases score
                if detection_ratio >= 0.1:  # 10% or more engines detect as malicious
                    score += 40
                elif detection_ratio >= 0.05:  # 5% or more
                    score += 25
                elif detection_ratio > 0:  # Any detection
                    score += 15

                # Categories can also indicate malicious intent
                categories = vt_result.get('categories', [])
                malicious_categories = ['malware', 'phishing', 'malicious', 'suspicious']
                for category in categories:
                    if any(mal_cat in category.lower() for mal_cat in malicious_categories):
                        score += 20
                        break

        return min(score, 100)  # Cap at 100

    def has_typosquatting_indicators(self, domain: str) -> bool:
        """Check for common typosquatting patterns"""
        typo_patterns = [
            r'.*[0-9]+.*',  # Numbers mixed in
            r'.*-+.*',      # Multiple hyphens
            r'.*(.)\1{2,}.*',  # Repeated characters
        ]

        for pattern in typo_patterns:
            if re.match(pattern, domain):
                return True
        return False

    def analyze_certificate(self, cert: Dict) -> Dict:
        """Analyze a certificate for phishing indicators including VirusTotal check"""
        domain = cert.get('name_value', '').lower()
        cert_id = cert.get('id')

        if not domain or not cert_id:
            return None

        # Check for keyword matches
        matched_keywords = []
        for keyword in self.target_keywords:
            if keyword in domain:
                matched_keywords.append(keyword)

        if not matched_keywords:
            return None

        # Check with VirusTotal if available
        vt_result = None
        if self.vt_checker:
            try:
                vt_result = self.check_with_virustotal(domain)
            except Exception as e:
                logger.error(f"VirusTotal check failed for {domain}: {e}")
                vt_result = {'found': False, 'error': str(e)}

        # Calculate risk score including VirusTotal data
        risk_score = self.calculate_risk_score(domain, matched_keywords, vt_result)

        # Check for suspicious patterns
        suspicious_patterns = []
        for pattern in self.suspicious_patterns:
            if re.match(pattern, domain):
                suspicious_patterns.append(pattern)

        analysis = {
            'cert_id': cert_id,
            'domain': domain,
            'issuer': cert.get('issuer_name', ''),
            'timestamp': cert.get('entry_timestamp', ''),
            'matched_keywords': matched_keywords,
            'suspicious_patterns': suspicious_patterns,
            'risk_score': risk_score,
            'is_suspicious': risk_score >= 40,
            'virustotal': vt_result
        }

        return analysis

    def save_analysis(self, analysis: Dict):
        """Save analysis results to database including VirusTotal data"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Save to processed_certs
            cursor.execute('''
                INSERT OR REPLACE INTO processed_certs 
                (cert_id, domain, issuer, timestamp, is_suspicious, keywords_matched, processed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                analysis['cert_id'],
                analysis['domain'],
                analysis['issuer'],
                analysis['timestamp'],
                1 if analysis['is_suspicious'] else 0,
                ','.join(analysis['matched_keywords']),
                datetime.now().isoformat()
            ))

            # Save to phishing_alerts if suspicious
            if analysis['is_suspicious']:
                vt_result = analysis.get('virustotal', {})
                if vt_result:
                    cursor.execute('''
                        INSERT INTO phishing_alerts 
                        (domain, cert_id, risk_score, matched_keywords, suspicious_patterns, 
                         detected_at, vt_positives, vt_total, vt_checked)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        analysis['domain'],
                        analysis['cert_id'],
                        analysis['risk_score'],
                        ','.join(analysis['matched_keywords']),
                        ','.join(analysis['suspicious_patterns']),
                        datetime.now().isoformat(),
                        vt_result.get('positives', 0) if vt_result.get('found') else 0,
                        vt_result.get('total', 0) if vt_result.get('found') else 0,
                        1 if vt_result else 0
                    ))

            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"Database error in save_analysis: {e}")

    def generate_alert(self, analysis: Dict):
        """Generate alert for suspicious domain including VirusTotal info"""
        logger.warning(f"🚨 PHISHING ALERT - Risk Score: {analysis['risk_score']}")
        logger.warning(f"   Domain: {analysis['domain']}")
        logger.warning(f"   Cert ID: {analysis['cert_id']}")
        logger.warning(f"   Keywords: {', '.join(analysis['matched_keywords'])}")
        logger.warning(f"   Issuer: {analysis['issuer']}")
        logger.warning(f"   Timestamp: {analysis['timestamp']}")

        if analysis['suspicious_patterns']:
            logger.warning(f"   Suspicious Patterns: {len(analysis['suspicious_patterns'])} detected")

        # VirusTotal information
        vt_result = analysis.get('virustotal')
        print(f"\n\n{vt_result = }")
        if vt_result:
            if vt_result.get('found'):
                positives = vt_result.get('positives', 0)
                total = vt_result.get('total', 0)
                if positives:
                    logger.warning(f"   VirusTotal: {positives}/{total} engines "
                                   f"flagged as "
                                   f"malicious")
                else:
                    logger.warning(f"  VirusTotal: 0 engines flagged as "
                                   f"malicious")

                if vt_result.get('permalink'):
                    logger.warning(f"   VirusTotal Report: {vt_result['permalink']}")

                categories = vt_result.get('categories', [])
                if categories:
                    logger.warning(f"   Categories: {', '.join(categories[:3])}")  # Show first 3
            else:
                if vt_result.get('cached'):
                    logger.warning(f"   VirusTotal: Not found in database (cached)")
                else:
                    logger.warning(f"   VirusTotal: Not found in database")
        else:
            logger.warning(f"   VirusTotal: Not checked (API key not provided)")

    def get_recent_alerts(self, hours: int = 24) -> List[Dict]:
        """Get recent phishing alerts including VirusTotal data"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            since = (datetime.now() - timedelta(hours=hours)).isoformat()

            cursor.execute('''
                SELECT domain, cert_id, risk_score, matched_keywords, detected_at,
                       vt_positives, vt_total, vt_checked
                FROM phishing_alerts 
                WHERE detected_at > ? 
                ORDER BY risk_score DESC, detected_at DESC
            ''', (since,))

            alerts = []
            for row in cursor.fetchall():
                alerts.append({
                    'domain': row[0],
                    'cert_id': row[1],
                    'risk_score': row[2],
                    'matched_keywords': row[3].split(',') if row[3] else [],
                    'detected_at': row[4],
                    'vt_positives': row[5] or 0,
                    'vt_total': row[6] or 0,
                    'vt_checked': bool(row[7])
                })

            conn.close()
            return alerts
        except sqlite3.Error as e:
            logger.error(f"Database error in get_recent_alerts: {e}")
            return []

    def monitor_certificates(self, interval: int = 300):
        """Main monitoring loop - simulates real-time monitoring"""
        logger.info("Starting certificate monitoring with VirusTotal integration...")
        logger.info(f"Monitoring keywords: {', '.join(self.target_keywords)}")
        logger.info(f"Check interval: {interval} seconds")
        logger.info(f"VirusTotal integration: {'Enabled' if self.vt_checker else 'Disabled'}")

        while True:
            try:
                logger.info("Fetching recent certificates...")

                # Get recent certificates containing target keywords
                recent_certs = self.get_recent_certs_by_keywords()
                logger.info(f"Retrieved {len(recent_certs)} certificates")

                new_certs = 0
                suspicious_certs = 0

                for cert in recent_certs:
                    cert_id = cert.get('id')

                    if not cert_id or self.is_cert_processed(cert_id):
                        continue

                    new_certs += 1

                    # Analyze certificate
                    analysis = self.analyze_certificate(cert)

                    if analysis:
                        # Save analysis
                        self.save_analysis(analysis)

                        # Generate alert if suspicious
                        if analysis['is_suspicious']:
                            suspicious_certs += 1
                            self.generate_alert(analysis)

                logger.info(f"Processed {new_certs} new certificates, {suspicious_certs} suspicious")

                # Show recent alerts summary
                recent_alerts = self.get_recent_alerts(1)  # Last hour
                if recent_alerts:
                    logger.info(f"Recent alerts in last hour: {len(recent_alerts)}")

                logger.info(f"Sleeping for {interval} seconds...")
                time.sleep(interval)

            except KeyboardInterrupt:
                logger.info("Monitoring stopped by user")
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                time.sleep(60)  # Wait before retrying

    def run_single_scan(self):
        """Run a single scan instead of continuous monitoring"""
        logger.info("Running single certificate scan with VirusTotal integration...")
        logger.info(f"VirusTotal integration: {'Enabled' if self.vt_checker else 'Disabled'}")

        recent_certs = self.get_recent_certs_by_keywords()
        logger.info(f"Retrieved {len(recent_certs)} certificates")

        new_certs = 0
        suspicious_certs = 0

        for cert in recent_certs:
            cert_id = cert.get('id')

            if not cert_id or self.is_cert_processed(cert_id):
                continue

            new_certs += 1

            analysis = self.analyze_certificate(cert)

            if analysis:
                self.save_analysis(analysis)

                if analysis['is_suspicious']:
                    suspicious_certs += 1
                    self.generate_alert(analysis)

        logger.info(f"Scan complete: {new_certs} new certificates, {suspicious_certs} suspicious")

        # Show summary of all alerts with VirusTotal data
        all_alerts = self.get_recent_alerts(24 * 7)  # Last week
        if all_alerts:
            logger.info(f"\n📊 SUMMARY - Recent alerts (last 7 days): {len(all_alerts)}")
            for alert in all_alerts[:10]:  # Show top 10
                vt_info = ""
                if alert['vt_checked']:
                    vt_info = f" [VT: {alert['vt_positives']}/{alert['vt_total']}]"
                logger.info(f"   {alert['domain']} (Score: {alert['risk_score']}){vt_info}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="CT Log Phishing Detection Tool with VirusTotal")
    parser.add_argument("--monitor", action="store_true",
                        help="Run continuous monitoring")
    parser.add_argument("--interval", type=int, default=300,
                        help="Monitoring interval in seconds (default: 300)")
    parser.add_argument("--single", action="store_true",
                        help="Run single scan instead of continuous monitoring")
    parser.add_argument("--vt-api-key", type=str,
                        help="VirusTotal API key for enhanced detection")

    args = parser.parse_args()

    vt_api_key = args.vt_api_key or os.getenv('VIRUSTOTAL_API_KEY')

    if not vt_api_key:
        logger.warning("No VirusTotal API key provided. Running without VirusTotal integration.")
        logger.warning("Set --vt-api-key or VIRUSTOTAL_API_KEY environment variable for enhanced detection.")

    detector = PhishingDetector(vt_api_key=vt_api_key)

    if args.monitor:
        detector.monitor_certificates(args.interval)
    else:
        detector.run_single_scan()
