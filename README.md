# MalScan 

**AI-Assisted Malware Behavior Analyzer**

MalScan is a professional, high-performance triage dashboard for advanced malware analysis. Built with a dark mode utility UI inspired by industry-leading EDR solutions like CrowdStrike and SentinelOne, MalScan provides both deep local static analysis and concurrent intelligence gathering from multiple threat feeds to deliver an actionable, weighted risk score.

## Features

- **Blazing Fast Concurrency**: Queries four top-tier threat intelligence APIs in parallel using Python's `ThreadPoolExecutor` so the UI never blocks.
- **Deep Static Engine**: Automatically parses both Windows PE and Linux ELF binaries. Extracts IAT lists, structural sections, entry points, and flags suspicious API calls.
- **Shannon Entropy Heatmaps**: A visual grid to immediately spot packed or encrypted segments of an executable.
- **Smart String Extraction**: Uses categorized Regex to segregate normal strings from Network IOCs (IPs/URLs), Paths (Registry/Files), Commands (PowerShell/Bash), and Malicious Keywords.
- **60/40 Weighted Risk Model**: Synthesizes a final confidence score. **Static Indicators** (40%) include entropy, suspicious IAT imports, and malicious strings. **Cloud Intelligence** (60%) leverages consensus from multiple sandboxes and threat databases.
- **Flat Premium Dark UI**: No fluff. Built with pure technical utility, `Outfit` typography, and strict functional data visualization.

## Tools and Technologies

This project was engineered using the following core stack:

### Frontend & UI
- **Streamlit**: Core web dashboard framework.
- **Plotly**: Interactive data visualization (Risk Gauges, Entropy Heatmaps).
- **Pandas**: Structured data tabling for Win32 API imports and network indicators.
- **Custom CSS / HTML**: Injected custom styling to achieve the flat dark mode, high-contrast premium UI featuring the *Outfit* typeface.

### Backend & Analysis Engine
- **Python 3.10+**: Core logic and runtime.
- **Pefile**: Deep structural parsing of Windows executables (`.exe`, `.dll`).
- **PyELFTools**: Parsing of Linux ELF format headers.
- **Hashlib, Math, Re**: Native Python libraries used to generate cryptographic hashes, calculate Shannon block entropy, and execute complex string pattern matching.
- **Concurrent.Futures**: Asynchronous thread pooling for simultaneous API orchestration.

### Threat Intelligence APIs
- **Hybrid Analysis API v2**: Cloud sandbox execution and full behavioral reporting lifecycle (Upload -> Poll -> Report).
- **VirusTotal API v3**: Antivirus detection ratios and vendor consensus.
- **MalwareBazaar API**: Hash lookup for known malware signatures and families.
- **URLScan.io API**: Reputation scanning for URLs extracted from binary strings.

## Installation

1. Clone the repository and navigate into the `streamlit-dashboard-v2` directory.
2. Ensure you have Python 3.10+ installed.
3. Install the required strictly pinned dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

Before launching MalScan, provide your API keys. By default, the app looks for environment variables or the values inside `config.py`.

```python
# config.py
HYBRID_ANALYSIS_API_KEY = "your_key_here"
VIRUSTOTAL_API_KEY      = "your_key_here"
URLSCAN_API_KEY         = "your_key_here"
# MalwareBazaar is free and requires no key for hash lookups.
```

If an API key is missing, MalScan gracefully degrades—it will grey out that panel and intelligently skip the request without crashing, relying entirely on the robust local static engine.

## Usage

Launch the dashboard locally:
```bash
streamlit run app.py --server.port 8504
```

- Upload any suspect `.exe`, `.dll`, `.elf`, `.bat`, `.ps1`, `.pdf`, or `.doc` file into the sidebar drop-zone.
- The file is securely kept solely in Python's `tempfile` buffer and is strictly flushed and explicitly removed from disk inside a `finally` block post-analysis to ensure host safety.

## Architecture Guidelines
All API calls are heavily guarded by a custom `@api_safe` decorator to prevent long timeouts, `HTTP 429` rate limiting bugs, or connection drops from freezing the analyzer during a triage process.
