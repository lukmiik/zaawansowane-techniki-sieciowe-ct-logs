import requests
import json
import time
import sqlite3
import re
import os
import subprocess
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


class GoogleSafeBrowsingChecker:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        self.session = requests.Session()

    def check_url(self, url: str) -> Dict:
        """Check URL against Google Safe Browsing"""
        if not self.api_key:
            return {'found': False, 'error': 'No API key provided'}

        payload = {
            "client": {
                "clientId": "phishing-detector",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        try:
            response = self.session.post(
                f"{self.base_url}?key={self.api_key}",
                json=payload,
                timeout=30
            )
            result = response.json()

            return {
                'found': 'matches' in result,
                'threats': result.get('matches', []),
                'threat_types': [match.get('threatType') for match in result.get('matches', [])]
            }
        except Exception as e:
            logger.error(f"Google Safe Browsing error: {e}")
            return {'found': False, 'error': str(e)}


class DNSTwistChecker:
    def __init__(self):
        self.dnstwist_available = self._check_dnstwist_availability()

    def _check_dnstwist_availability(self) -> bool:
        """Check if dnstwist is available"""
        try:
            subprocess.run(['dnstwist', '--help'], capture_output=True, timeout=10)
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            logger.warning("dnstwist not found. Install with: pip install dnstwist")
            return False

    def generate_typosquatting_domains(self, domain: str) -> List[Dict]:
        """Generate typosquatting variants using dnstwist"""
        if not self.dnstwist_available:
            return []

        try:
            cmd = ['dnstwist', '--format', 'json', '--registered', domain]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode == 0:
                variants = json.loads(result.stdout)
                return [v for v in variants if v.get('domain') != domain]
            return []
        except Exception as e:
            logger.error(f"DNSTwist error for {domain}: {e}")
            return []


class PhishTankChecker:
    def __init__(self):
        self.base_url = "http://checkurl.phishtank.com/checkurl/"
        self.session = requests.Session()

    def check_url(self, url: str) -> Dict:
        """Check URL against PhishTank"""
        data = {
            'url': url,
            'format': 'json'
        }

        try:
            response = self.session.post(self.base_url, data=data, timeout=30)
            result = response.json()

            return {
                'found': result.get('results', {}).get('in_database', False),
                'verified': result.get('results', {}).get('verified', False),
                'phish_id': result.get('results', {}).get('phish_id'),
                'submission_time': result.get('results', {}).get('submission_time')
            }
        except Exception as e:
            logger.error(f"PhishTank error: {e}")
            return {'found': False, 'error': str(e)}


class PhishingDetector:
    def __init__(self, db_path: str = "phishing_monitor.db", vt_api_key: str = None, gsb_api_key: str = None):
        self.db_path = db_path
        self.vt_checker = VirusTotalChecker(vt_api_key) if vt_api_key else None
        self.gsb_checker = GoogleSafeBrowsingChecker(gsb_api_key) if gsb_api_key else None
        self.dnstwist_checker = DNSTwistChecker()
        self.phishtank_checker = PhishTankChecker()

        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'PhishingDetector/1.0'
        })

        # Rozszerzona lista słów kluczowych
        self.target_keywords = [
            'paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook',
            # 'instagram', 'twitter', 'linkedin', 'netflix', 'spotify',
            # 'bankofamerica', 'chase', 'wellsfargo', 'citibank',
            # 'societegenerale', 'bnpparibas', 'creditagricole',
            # 'gmail', 'outlook', 'yahoo', 'dropbox', 'github',
            # # Polskie banki
            # 'pkobp', 'mbank', 'ingbank', 'santander', 'aliorbank',
            # 'pekao', 'bzwbk', 'getin', 'eurobank'
        ]

        # Suspicious patterns
        self.suspicious_patterns = [
            r'.*-?(secure|verify|update|login|account|support)-?.*',  # Phishing słowa
            r'.*[0-9]{6,}.*',  # Długie ciągi cyfr (nie 4)
            r'.*-[a-z0-9]{10,}$',  # Bardzo długie losowe sufiksy
            r'.*\.(tk|ml|ga|cf|top)$',  # Podejrzane TLD
            r'.*-?(bank|pay|secure)-?[0-9]+.*',  # Bank + cyfry
        ]
        self.init_database()

    def init_database(self):
        """Initialize SQLite database for tracking processed certificates"""
        needs_recreation = False

        if os.path.exists(self.db_path):
            try:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()

                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='processed_certs'")
                if not cursor.fetchone():
                    needs_recreation = True
                else:
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
            if os.path.exists(self.db_path):
                os.remove(self.db_path)
                logger.info("Removed old database with incorrect schema")

            self._create_database()
        else:
            logger.info("Database schema is correct")

    def _create_database(self):
        """Create database with proper schema including all integrations"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Drop tables if they exist
        cursor.execute('DROP TABLE IF EXISTS processed_certs')
        cursor.execute('DROP TABLE IF EXISTS phishing_alerts')
        cursor.execute('DROP TABLE IF EXISTS virustotal_checks')
        cursor.execute('DROP TABLE IF EXISTS dnstwist_results')
        cursor.execute('DROP TABLE IF EXISTS gsb_checks')
        cursor.execute('DROP TABLE IF EXISTS phishtank_checks')

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
                gsb_threat INTEGER DEFAULT 0,
                phishtank_threat INTEGER DEFAULT 0,
                typosquatting_variants INTEGER DEFAULT 0,
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

        # Create DNSTwist results table
        cursor.execute('''
            CREATE TABLE dnstwist_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_domain TEXT NOT NULL,
                variant_domain TEXT NOT NULL,
                fuzzer TEXT,
                registered INTEGER DEFAULT 0,
                checked_at TEXT NOT NULL
            )
        ''')

        # Create Google Safe Browsing checks table
        cursor.execute('''
            CREATE TABLE gsb_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                threat_found INTEGER DEFAULT 0,
                threat_types TEXT,
                checked_at TEXT NOT NULL,
                UNIQUE(url)
            )
        ''')

        # Create PhishTank checks table
        cursor.execute('''
            CREATE TABLE phishtank_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                in_database INTEGER DEFAULT 0,
                verified INTEGER DEFAULT 0,
                phish_id TEXT,
                checked_at TEXT NOT NULL,
                UNIQUE(url)
            )
        ''')

        # Create indexes for better performance
        cursor.execute('CREATE INDEX idx_processed_certs_cert_id ON processed_certs(cert_id)')
        cursor.execute('CREATE INDEX idx_processed_certs_domain ON processed_certs(domain)')
        cursor.execute('CREATE INDEX idx_phishing_alerts_detected_at ON phishing_alerts(detected_at)')
        cursor.execute('CREATE INDEX idx_phishing_alerts_risk_score ON phishing_alerts(risk_score)')
        cursor.execute('CREATE INDEX idx_virustotal_checks_domain ON virustotal_checks(domain)')
        cursor.execute('CREATE INDEX idx_dnstwist_results_original ON dnstwist_results(original_domain)')

        conn.commit()
        conn.close()
        logger.info("Database created successfully with all integrations")

    def query_crtsh(self, domain_pattern: str = None, limit: int = 1000) -> List[Dict]:
        """Query crt.sh API for certificates"""
        try:
            if domain_pattern:
                url = f"https://crt.sh/?q={domain_pattern}&output=json"
            else:
                url = f"https://crt.sh/?output=json"

            response = self.session.get(url, timeout=30)
            response.raise_for_status()

            if response.text.strip():
                certs = json.loads(response.text)
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
            pattern = f"%.{keyword}.%"
            certs = self.query_crtsh(pattern, limit=10)

            if certs:
                logger.info(f"Found {len(certs)} certificates for keyword '{keyword}'")
                all_certs.extend(certs)

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

        cached_result = self.check_virustotal_cache(domain)
        if cached_result:
            logger.info(f"Using cached VirusTotal result for {domain}")
            return cached_result

        logger.info(f"Checking {domain} with VirusTotal API")
        vt_result = self.vt_checker.check_domain_reputation(domain)
        self.save_virustotal_result(domain, vt_result)

        return vt_result

    def check_with_google_safe_browsing(self, domain: str) -> Dict:
        """Check domain with Google Safe Browsing"""
        if not self.gsb_checker:
            return {'found': False, 'error': 'Google Safe Browsing API key not provided'}

        url = f"https://{domain}"
        return self.gsb_checker.check_url(url)

    def check_with_phishtank(self, domain: str) -> Dict:
        """Check domain with PhishTank"""
        url = f"https://{domain}"
        return self.phishtank_checker.check_url(url)

    def generate_typosquatting_variants(self, domain: str) -> List[Dict]:
        """Generate typosquatting variants for domain"""
        base_domain = domain.split('.')[0]  # Get base domain without TLD
        return self.dnstwist_checker.generate_typosquatting_domains(base_domain)

    def calculate_enhanced_risk_score(self, analysis: Dict) -> int:
        """Calculate enhanced risk score with all integrations"""
        score = 0
        domain = analysis['domain']
        matched_keywords = analysis['matched_keywords']

        # Base score for keyword matches
        score += len(matched_keywords) * 10

        # Check for suspicious patterns
        for pattern in self.suspicious_patterns:
            if re.match(pattern, domain.lower()):
                score += 20

        # Check for typosquatting indicators
        if self.has_typosquatting_indicators(domain):
            score += 30

        # Domain length
        if len(domain) > 50:
            score += 15

        # Multiple subdomains
        subdomain_count = domain.count('.')
        if subdomain_count > 3:
            score += 10

        # VirusTotal integration
        vt_result = analysis.get('virustotal')
        if vt_result and vt_result.get('found'):
            positives = vt_result.get('positives', 0)
            total = vt_result.get('total', 0)

            if total > 0:
                detection_ratio = positives / total
                if detection_ratio >= 0.1:
                    score += 40
                elif detection_ratio >= 0.05:
                    score += 25
                elif detection_ratio > 0:
                    score += 15

        # Google Safe Browsing
        if analysis.get('gsb_threat'):
            score += 35

        # PhishTank
        if analysis.get('phishtank_threat'):
            score += 30

        # DNSTwist variants
        variants_count = analysis.get('typosquatting_variants', 0)
        if variants_count > 10:
            score += 20
        elif variants_count > 5:
            score += 10

        return min(score, 100)

    def has_typosquatting_indicators(self, domain: str) -> bool:
        """Check for common typosquatting patterns"""
        typo_patterns = [
            r'.*[0-9]+.*',
            r'.*-+.*',
            r'.*(.)\1{2,}.*',
        ]

        for pattern in typo_patterns:
            if re.match(pattern, domain):
                return True
        return False

    def analyze_certificate_enhanced(self, cert: Dict) -> Dict:
        """Enhanced analysis with all integrations"""
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

        # Check with all services
        vt_result = None
        gsb_result = None
        phishtank_result = None
        typosquatting_variants = []

        try:
            # VirusTotal check
            if self.vt_checker:
                vt_result = self.check_with_virustotal(domain)

            # Google Safe Browsing check
            if self.gsb_checker:
                gsb_result = self.check_with_google_safe_browsing(domain)

            # PhishTank check
            phishtank_result = self.check_with_phishtank(domain)

            # DNSTwist check
            typosquatting_variants = self.generate_typosquatting_variants(domain)

        except Exception as e:
            logger.error(f"Error during enhanced analysis for {domain}: {e}")

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
            'virustotal': vt_result,
            'gsb_threat': gsb_result.get('found', False) if gsb_result else False,
            'phishtank_threat': phishtank_result.get('found', False) if phishtank_result else False,
            'typosquatting_variants': len(typosquatting_variants)
        }

        # Calculate enhanced risk score
        analysis['risk_score'] = self.calculate_enhanced_risk_score(analysis)
        analysis['is_suspicious'] = analysis['risk_score'] >= 40

        return analysis

    def save_enhanced_analysis(self, analysis: Dict):
        """Save enhanced analysis results to database"""
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
                cursor.execute('''
                    INSERT INTO phishing_alerts 
                    (domain, cert_id, risk_score, matched_keywords, suspicious_patterns, 
                     detected_at, vt_positives, vt_total, vt_checked, gsb_threat, 
                     phishtank_threat, typosquatting_variants)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    analysis['domain'],
                    analysis['cert_id'],
                    analysis['risk_score'],
                    ','.join(analysis['matched_keywords']),
                    ','.join(analysis['suspicious_patterns']),
                    datetime.now().isoformat(),
                    vt_result.get('positives', 0) if vt_result and vt_result.get('found') else 0,
                    vt_result.get('total', 0) if vt_result and vt_result.get('found') else 0,
                    1 if vt_result else 0,
                    1 if analysis.get('gsb_threat') else 0,
                    1 if analysis.get('phishtank_threat') else 0,
                    analysis.get('typosquatting_variants', 0)
                ))

            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"Database error in save_enhanced_analysis: {e}")

    def generate_enhanced_alert(self, analysis: Dict):
        """Generate enhanced alert with all integration data"""
        logger.warning(f"   ENHANCED PHISHING ALERT - Risk Score: {analysis['risk_score']}")
        logger.warning(f"   Domain: {analysis['domain']}")
        logger.warning(f"   Cert ID: {analysis['cert_id']}")
        logger.warning(f"   Keywords: {', '.join(analysis['matched_keywords'])}")
        logger.warning(f"   Issuer: {analysis['issuer']}")
        logger.warning(f"   Timestamp: {analysis['timestamp']}")

        if analysis['suspicious_patterns']:
            logger.warning(f"   Suspicious Patterns: {len(analysis['suspicious_patterns'])} detected")

        # VirusTotal information
        vt_result = analysis.get('virustotal')
        if vt_result:
            if vt_result.get('found'):
                positives = vt_result.get('positives', 0)
                total = vt_result.get('total', 0)
                logger.warning(f"   VirusTotal: {positives}/{total} engines flagged as malicious")
                if vt_result.get('permalink'):
                    logger.warning(f"   VirusTotal Report: {vt_result['permalink']}")
            else:
                logger.warning(f"   VirusTotal: Not found in database")

        # Google Safe Browsing
        if analysis.get('gsb_threat'):
            logger.warning(f"   Google Safe Browsing: THREAT DETECTED")
        else:
            logger.warning(f"   Google Safe Browsing: Clean")

        # PhishTank
        if analysis.get('phishtank_threat'):
            logger.warning(f"   PhishTank: KNOWN PHISHING SITE")
        else:
            logger.warning(f"   PhishTank: Not in database")

        # DNSTwist
        variants_count = analysis.get('typosquatting_variants', 0)
        if variants_count > 0:
            logger.warning(f"   Typosquatting Variants: {variants_count} similar domains found")

    def run_enhanced_scan(self):
        """Run enhanced single scan with all integrations"""
        logger.info("Running enhanced certificate scan with all integrations...")
        logger.info(f"VirusTotal: {'Enabled' if self.vt_checker else 'Disabled'}")
        logger.info(f"Google Safe Browsing: {'Enabled' if self.gsb_checker else 'Disabled'}")
        logger.info(f"DNSTwist: {'Enabled' if self.dnstwist_checker.dnstwist_available else 'Disabled'}")
        logger.info(f"PhishTank: Enabled")

        recent_certs = self.get_recent_certs_by_keywords()
        logger.info(f"Retrieved {len(recent_certs)} certificates")

        new_certs = 0
        suspicious_certs = 0

        for cert in recent_certs:
            cert_id = cert.get('id')

            if not cert_id or self.is_cert_processed(cert_id):
                continue

            new_certs += 1

            analysis = self.analyze_certificate_enhanced(cert)

            if analysis:
                self.save_enhanced_analysis(analysis)

                if analysis['is_suspicious']:
                    suspicious_certs += 1
                    self.generate_enhanced_alert(analysis)

        logger.info(f"Enhanced scan complete: {new_certs} new certificates, {suspicious_certs} suspicious")

        # Show summary
        all_alerts = self.get_recent_alerts(24 * 7)
        if all_alerts:
            logger.info(f"\n📊 ENHANCED SUMMARY - Recent alerts (last 7 days): {len(all_alerts)}")
            for alert in all_alerts[:10]:
                threat_indicators = []
                if alert.get('vt_positives', 0) > 0:
                    threat_indicators.append(f"VT:{alert['vt_positives']}/{alert['vt_total']}")
                if alert.get('gsb_threat'):
                    threat_indicators.append("GSB")
                if alert.get('phishtank_threat'):
                    threat_indicators.append("PT")
                if alert.get('typosquatting_variants', 0) > 0:
                    threat_indicators.append(f"TS:{alert['typosquatting_variants']}")

                indicators_str = f" [{','.join(threat_indicators)}]" if threat_indicators else ""
                logger.info(f"   {alert['domain']} (Score: {alert['risk_score']}){indicators_str}")

    def get_recent_alerts(self, hours: int = 24) -> List[Dict]:
        """Get recent phishing alerts with enhanced data"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            since = (datetime.now() - timedelta(hours=hours)).isoformat()

            cursor.execute('''
                SELECT domain, cert_id, risk_score, matched_keywords, detected_at,
                       vt_positives, vt_total, vt_checked, gsb_threat, phishtank_threat,
                       typosquatting_variants
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
                    'vt_checked': bool(row[7]),
                    'gsb_threat': bool(row[8]),
                    'phishtank_threat': bool(row[9]),
                    'typosquatting_variants': row[10] or 0
                })

            conn.close()
            return alerts
        except sqlite3.Error as e:
            logger.error(f"Database error in get_recent_alerts: {e}")
            return []

    def monitor_certificates_enhanced(self, interval: int = 300):
        """Enhanced monitoring loop with all integrations"""
        logger.info("Starting enhanced certificate monitoring...")
        logger.info(f"Monitoring keywords: {', '.join(self.target_keywords)}")
        logger.info(f"Check interval: {interval} seconds")
        logger.info(f"VirusTotal: {'Enabled' if self.vt_checker else 'Disabled'}")
        logger.info(f"Google Safe Browsing: {'Enabled' if self.gsb_checker else 'Disabled'}")
        logger.info(f"DNSTwist: {'Enabled' if self.dnstwist_checker.dnstwist_available else 'Disabled'}")

        while True:
            try:
                logger.info("Fetching recent certificates...")

                recent_certs = self.get_recent_certs_by_keywords()
                logger.info(f"Retrieved {len(recent_certs)} certificates")

                new_certs = 0
                suspicious_certs = 0

                for cert in recent_certs:
                    cert_id = cert.get('id')

                    if not cert_id or self.is_cert_processed(cert_id):
                        continue

                    new_certs += 1

                    analysis = self.analyze_certificate_enhanced(cert)

                    if analysis:
                        self.save_enhanced_analysis(analysis)

                        if analysis['is_suspicious']:
                            suspicious_certs += 1
                            self.generate_enhanced_alert(analysis)

                logger.info(f"Processed {new_certs} new certificates, {suspicious_certs} suspicious")

                recent_alerts = self.get_recent_alerts(1)
                if recent_alerts:
                    logger.info(f"Recent alerts in last hour: {len(recent_alerts)}")

                logger.info(f"Sleeping for {interval} seconds...")
                time.sleep(interval)

            except KeyboardInterrupt:
                logger.info("Enhanced monitoring stopped by user")
                break
            except Exception as e:
                logger.error(f"Error in enhanced monitoring loop: {e}")
                time.sleep(60)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Enhanced CT Log Phishing Detection Tool")
    parser.add_argument("--monitor", action="store_true",
                        help="Run continuous monitoring")
    parser.add_argument("--interval", type=int, default=300,
                        help="Monitoring interval in seconds (default: 300)")
    parser.add_argument("--single", action="store_true",
                        help="Run single enhanced scan")
    parser.add_argument("--vt-api-key", type=str,
                        help="VirusTotal API key")
    parser.add_argument("--gsb-api-key", type=str,
                        help="Google Safe Browsing API key")

    args = parser.parse_args()

    vt_api_key = args.vt_api_key or os.getenv('VIRUSTOTAL_API_KEY')
    gsb_api_key = args.gsb_api_key or os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')

    if not vt_api_key:
        logger.warning("No VirusTotal API key provided.")
    if not gsb_api_key:
        logger.warning("No Google Safe Browsing API key provided.")

    detector = PhishingDetector(vt_api_key=vt_api_key, gsb_api_key=gsb_api_key)

    if args.monitor:
        detector.monitor_certificates_enhanced(args.interval)
    else:
        detector.run_enhanced_scan()
