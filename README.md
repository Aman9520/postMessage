# Advanced XSS Scanner

A concurrent, multi-type XSS vulnerability scanner with smart crawling, filter bypass techniques, and detailed HTML/JSON reporting.

## Features

- **Reflected XSS** — URL parameters & form fields
- **Stored XSS** — Marker injection + re-visit detection
- **DOM XSS** — Fragment-based testing, sink detection
- **Blind XSS** — Callback-based out-of-band payloads
- **Smart crawling** — Recursive spider with depth control
- **Filter bypass** — 40+ bypass techniques (encoding, case, events, etc.)
- **Context detection** — Detects HTML/attribute/JS context and selects best payload
- **Concurrent scanning** — ThreadPoolExecutor for speed
- **Reports** — Beautiful HTML + JSON output

---

## Install

```bash
pip install -r requirements.txt
```

---

## Usage

### Basic scan
```bash
python scanner.py http://target.com
```

### Full options
```bash
python scanner.py http://target.com \
  --depth 4 \
  --threads 20 \
  --delay 0.1 \
  --callback https://your-burp-collaborator.com/xss \
  --cookies "session=abc123; token=xyz" \
  --header "Authorization: Bearer TOKEN" \
  --output ./my-reports
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-d, --depth` | 3 | Crawl depth |
| `-t, --threads` | 10 | Concurrent threads |
| `--timeout` | 10 | Request timeout (seconds) |
| `--delay` | 0.2 | Delay between requests |
| `--callback` | — | Blind XSS callback URL (Burp Collaborator, interactsh) |
| `--cookies` | — | Session cookies |
| `--header` | — | Extra HTTP headers (repeatable) |
| `-o, --output` | reports/ | Output directory |

---

## Output

After scanning, two files are created in the output directory:
- `xss_report_TIMESTAMP.html` — Visual dashboard
- `xss_report_TIMESTAMP.json` — Machine-readable data

---

## Architecture

```
AdvancedXSSScanner
├── Crawler           → Recursive spider, extracts forms & URL params
├── XSSTester
│   ├── test_reflected_url_param()   → GET param fuzzing
│   ├── test_reflected_form()        → POST/GET form fuzzing
│   ├── inject_stored_markers()      → Stored XSS injection
│   ├── check_stored_markers()       → Stored XSS verification
│   ├── test_dom_xss()              → Fragment & sink detection
│   └── test_blind_xss()            → OOB callback payloads
├── ContextDetector   → html_body | attribute | js | url
├── PayloadDB         → 40+ payloads across all categories
└── ReportGenerator   → HTML + JSON reports
```

---

## Legal Notice

**Only use this tool on systems you own or have explicit written authorization to test.**
Unauthorized scanning is illegal under the Computer Fraud and Abuse Act (US), Computer Misuse Act (UK), and equivalent laws worldwide.

Safe testing environments:
- [DVWA](https://dvwa.co.uk/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTheBox](https://hackthebox.com/)
- Bug bounty programs (HackerOne, Bugcrowd)
