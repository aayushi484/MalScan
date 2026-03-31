"""
AI-Assisted Malware Behavior Analyzer — API Clients
Full lifecycle: Hybrid Analysis (upload→poll→report), VirusTotal v3,
MalwareBazaar, URLScan.io. All network calls are wrapped with error handling.
Uses concurrent.futures for parallel execution.
"""
import functools
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional

import requests

from config import (
    HYBRID_ANALYSIS_API_KEY, HYBRID_ANALYSIS_BASE,
    VIRUSTOTAL_API_KEY, VIRUSTOTAL_BASE,
    MALWAREBAZAAR_BASE,
    URLSCAN_API_KEY, URLSCAN_BASE,
    REQUEST_TIMEOUT, POLL_INTERVAL, MAX_POLL_ATTEMPTS,
    THREAD_POOL_WORKERS,
)


# ──────────────────────────────────────────────────────────────────
# Error-handling decorator for all network requests
# ──────────────────────────────────────────────────────────────────
def api_safe(source_name: str):
    """Decorator that wraps API calls with standardised error handling."""
    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs) -> Dict[str, Any]:
            try:
                return fn(*args, **kwargs)
            except requests.Timeout:
                return {"source": source_name, "status": "TIMEOUT", "data": {}, "error": "Request timed out"}
            except requests.ConnectionError:
                return {"source": source_name, "status": "CONN_ERROR", "data": {}, "error": "Connection failed"}
            except requests.HTTPError as e:
                code = e.response.status_code if e.response is not None else "?"
                return {"source": source_name, "status": "HTTP_ERROR", "data": {}, "error": f"HTTP {code}"}
            except Exception as e:
                return {"source": source_name, "status": "ERROR", "data": {}, "error": str(e)[:200]}
        return wrapper
    return decorator


# ──────────────────────────────────────────────────────────────────
# Hybrid Analysis v2 — Full Lifecycle
# ──────────────────────────────────────────────────────────────────
@api_safe("Hybrid Analysis")
def hybrid_analysis_submit(file_path: str) -> Dict[str, Any]:
    """Submit file to Hybrid Analysis sandbox and poll until report is ready."""
    result: Dict[str, Any] = {"source": "Hybrid Analysis", "status": "SKIPPED", "data": {}, "error": None}

    if not HYBRID_ANALYSIS_API_KEY:
        result["error"] = "API key not configured"
        return result

    headers = {
        "api-key": HYBRID_ANALYSIS_API_KEY,
        "User-Agent": "Falcon Sandbox",
        "accept": "application/json",
    }

    # Step 1: Submit file
    with open(file_path, "rb") as f:
        files = {"file": f}
        data = {"environment_id": 160}  # Windows 10 64-bit
        resp = requests.post(
            f"{HYBRID_ANALYSIS_BASE}/submit/file",
            headers=headers, files=files, data=data,
            timeout=REQUEST_TIMEOUT
        )

    if resp.status_code == 429:
        result["status"] = "RATE_LIMITED"
        result["error"] = "Rate limit exceeded"
        return result

    resp.raise_for_status()
    submit_data = resp.json()
    job_id = submit_data.get("job_id")
    sha256 = submit_data.get("sha256")

    if not job_id and not sha256:
        result["status"] = "ERROR"
        result["error"] = "No job_id or sha256 returned from submission"
        return result

    # Step 2: Poll for completion
    report_url = f"{HYBRID_ANALYSIS_BASE}/report/{sha256}/summary"
    for attempt in range(MAX_POLL_ATTEMPTS):
        time.sleep(POLL_INTERVAL)
        poll_resp = requests.get(report_url, headers=headers, timeout=REQUEST_TIMEOUT)

        if poll_resp.status_code == 200:
            report = poll_resp.json()
            if report.get("state") == "SUCCESS" or report.get("verdict"):
                result["status"] = "SUCCESS"
                result["data"] = {
                    "verdict": report.get("verdict", "unknown"),
                    "threat_score": report.get("threat_score", 0),
                    "threat_level": report.get("threat_level", 0),
                    "av_detect": report.get("av_detect", 0),
                    "vx_family": report.get("vx_family", ""),
                    "tags": report.get("tags", []),
                    "mitre_attcks": report.get("mitre_attcks", []),
                    "network": report.get("domains", []) + report.get("hosts", []),
                    "processes": report.get("processes", []),
                    "classification_tags": report.get("classification_tags", []),
                    "submissions": report.get("submissions", []),
                }
                return result

        if poll_resp.status_code == 404:
            continue  # Not ready yet

    result["status"] = "TIMEOUT"
    result["error"] = f"Report not ready after {MAX_POLL_ATTEMPTS * POLL_INTERVAL}s"
    return result


@api_safe("Hybrid Analysis")
def hybrid_analysis_hash_lookup(sha256: str) -> Dict[str, Any]:
    """Quick hash lookup on Hybrid Analysis (no file upload, instant if cached)."""
    result: Dict[str, Any] = {"source": "Hybrid Analysis", "status": "SKIPPED", "data": {}, "error": None}

    if not HYBRID_ANALYSIS_API_KEY:
        result["error"] = "API key not configured"
        return result

    headers = {
        "api-key": HYBRID_ANALYSIS_API_KEY,
        "User-Agent": "Falcon Sandbox",
        "accept": "application/json",
    }

    resp = requests.get(
        f"{HYBRID_ANALYSIS_BASE}/overview/{sha256}",
        headers=headers, timeout=REQUEST_TIMEOUT
    )

    if resp.status_code == 200:
        data = resp.json()
        result["status"] = "SUCCESS"
        result["data"] = {
            "verdict": data.get("verdict", "unknown"),
            "threat_score": data.get("threat_score", 0),
            "av_detect": data.get("av_detect", 0),
            "vx_family": data.get("vx_family", ""),
            "tags": data.get("tags", []),
            "mitre_attcks": data.get("mitre_attcks", []),
        }
    elif resp.status_code == 404:
        result["status"] = "NOT_FOUND"
        result["error"] = "Hash not found"
    elif resp.status_code == 429:
        result["status"] = "RATE_LIMITED"
        result["error"] = "Rate limit exceeded"
    else:
        resp.raise_for_status()

    return result


# ──────────────────────────────────────────────────────────────────
# VirusTotal v3
# ──────────────────────────────────────────────────────────────────
@api_safe("VirusTotal")
def query_virustotal(sha256: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {"source": "VirusTotal", "status": "SKIPPED", "data": {}, "error": None}

    if not VIRUSTOTAL_API_KEY:
        result["error"] = "API key not configured"
        return result

    resp = requests.get(
        f"{VIRUSTOTAL_BASE}/files/{sha256}",
        headers={"x-apikey": VIRUSTOTAL_API_KEY},
        timeout=REQUEST_TIMEOUT,
    )

    if resp.status_code == 200:
        attrs = resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        # Top detections
        verdicts = []
        for vendor, info in attrs.get("last_analysis_results", {}).items():
            if info.get("category") in ("malicious", "suspicious"):
                verdicts.append({"vendor": vendor, "category": info["category"], "result": info.get("result", "")})
                if len(verdicts) >= 15:
                    break

        result["status"] = "SUCCESS"
        result["data"] = {
            "detection_ratio": f"{stats.get('malicious',0)}/{sum(stats.values())}",
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": attrs.get("reputation", 0),
            "tags": attrs.get("tags", []),
            "type_description": attrs.get("type_description", "N/A"),
            "vendor_verdicts": verdicts,
        }
    elif resp.status_code == 404:
        result["status"] = "NOT_FOUND"
        result["error"] = "Hash not in VT database"
    elif resp.status_code == 429:
        result["status"] = "RATE_LIMITED"
        result["error"] = "Rate limit exceeded"
    else:
        resp.raise_for_status()

    return result


# ──────────────────────────────────────────────────────────────────
# MalwareBazaar
# ──────────────────────────────────────────────────────────────────
@api_safe("MalwareBazaar")
def query_malwarebazaar(sha256: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {"source": "MalwareBazaar", "status": "SKIPPED", "data": {}, "error": None}

    resp = requests.post(MALWAREBAZAAR_BASE, data={"query": "get_info", "hash": sha256}, timeout=REQUEST_TIMEOUT)
    body = resp.json()

    if body.get("query_status") == "ok":
        entry = body.get("data", [{}])[0]
        result["status"] = "SUCCESS"
        result["data"] = {
            "family": entry.get("signature", "Unknown"),
            "file_type": entry.get("file_type", "N/A"),
            "delivery": entry.get("delivery_method", "N/A"),
            "first_seen": entry.get("first_seen", "N/A"),
            "tags": entry.get("tags", []),
            "origin": entry.get("origin_country", "N/A"),
        }
    elif body.get("query_status") == "hash_not_found":
        result["status"] = "NOT_FOUND"
        result["error"] = "Not in MalwareBazaar"
    else:
        result["status"] = "ERROR"
        result["error"] = body.get("query_status", "Unknown")

    return result


# ──────────────────────────────────────────────────────────────────
# URLScan.io
# ──────────────────────────────────────────────────────────────────
@api_safe("URLScan.io")
def query_urlscan(urls: List[str]) -> Dict[str, Any]:
    result: Dict[str, Any] = {"source": "URLScan.io", "status": "SKIPPED", "data": {"results": []}, "error": None}

    if not urls:
        result["error"] = "No URLs to scan"
        return result
    if not URLSCAN_API_KEY:
        result["error"] = "API key not configured"
        return result

    headers = {"API-Key": URLSCAN_API_KEY}
    scanned = []
    for url in urls[:5]:
        try:
            r = requests.get(f"{URLSCAN_BASE}/search/?q=page.url:{url}", headers=headers, timeout=REQUEST_TIMEOUT)
            if r.status_code == 200:
                hits = r.json().get("results", [])
                if hits:
                    top = hits[0]
                    v = top.get("verdicts", {}).get("overall", {})
                    scanned.append({"url": url, "malicious": v.get("malicious", False), "score": v.get("score", 0)})
                else:
                    scanned.append({"url": url, "malicious": None, "score": 0})
        except Exception:
            scanned.append({"url": url, "malicious": None, "score": -1})

    result["data"]["results"] = scanned
    if scanned:
        result["status"] = "SUCCESS"
    return result


# ──────────────────────────────────────────────────────────────────
# Orchestrator — Concurrent Execution
# ──────────────────────────────────────────────────────────────────
class APIOrchestrator:
    def __init__(self, sha256: str, urls: Optional[List[str]] = None):
        self.sha256 = sha256
        self.urls = urls or []

    def run_all(self, progress_callback=None) -> Dict[str, Dict[str, Any]]:
        """Execute all API calls concurrently. Returns dict keyed by source name."""
        tasks = {
            "hybrid_analysis": lambda: hybrid_analysis_hash_lookup(self.sha256),
            "virustotal": lambda: query_virustotal(self.sha256),
            "malwarebazaar": lambda: query_malwarebazaar(self.sha256),
            "urlscan": lambda: query_urlscan(self.urls),
        }
        results: Dict[str, Dict[str, Any]] = {}

        with ThreadPoolExecutor(max_workers=THREAD_POOL_WORKERS) as pool:
            futures = {pool.submit(fn): name for name, fn in tasks.items()}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    results[name] = future.result()
                except Exception as e:
                    results[name] = {"source": name, "status": "ERROR", "data": {}, "error": str(e)[:200]}
                if progress_callback:
                    progress_callback(name, len(results), len(tasks))

        return results

    @staticmethod
    def api_available(key: str) -> bool:
        return bool(key and key.strip())

    @staticmethod
    def compute_consensus(api_results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        queried, flagged, families = 0, 0, []

        ha = api_results.get("hybrid_analysis", {})
        if ha.get("status") == "SUCCESS":
            queried += 1
            v = ha.get("data", {}).get("verdict", "")
            if v in ("malicious", "suspicious"):
                flagged += 1
            fam = ha.get("data", {}).get("vx_family", "")
            if fam:
                families.append(fam)

        vt = api_results.get("virustotal", {})
        if vt.get("status") == "SUCCESS":
            queried += 1
            if vt.get("data", {}).get("malicious", 0) > 0:
                flagged += 1

        mb = api_results.get("malwarebazaar", {})
        if mb.get("status") == "SUCCESS":
            queried += 1
            flagged += 1
            fam = mb.get("data", {}).get("family", "")
            if fam and fam != "Unknown":
                families.append(fam)

        us = api_results.get("urlscan", {})
        if us.get("status") == "SUCCESS":
            queried += 1
            if any(r.get("malicious") for r in us.get("data", {}).get("results", [])):
                flagged += 1

        if queried == 0:
            conf, label = "NONE", "No API data"
        elif flagged >= 3:
            conf, label = "CRITICAL", "Multiple sources confirm threat"
        elif flagged == 2:
            conf, label = "HIGH", "Cross-source detection"
        elif flagged == 1:
            conf, label = "MEDIUM", "Single source detection"
        else:
            conf, label = "LOW", "No detections"

        return {"queried": queried, "flagged": flagged, "confidence": conf, "label": label, "families": list(set(families))}
