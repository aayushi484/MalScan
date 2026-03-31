"""
AI-Assisted Malware Behavior Analyzer — Configuration
"""
import os

# ──────────────────────────────────────────────────────────────────
# API Keys
# ──────────────────────────────────────────────────────────────────
HYBRID_ANALYSIS_API_KEY = os.getenv(
    "HYBRID_ANALYSIS_API_KEY",
    "..."
)
VIRUSTOTAL_API_KEY = os.getenv(
    "VIRUSTOTAL_API_KEY",
    "..."
)
URLSCAN_API_KEY = os.getenv(
    "URLSCAN_API_KEY",
    "..."
)

# ──────────────────────────────────────────────────────────────────
# API Endpoints
# ──────────────────────────────────────────────────────────────────
HYBRID_ANALYSIS_BASE = "https://www.hybrid-analysis.com/api/v2"
VIRUSTOTAL_BASE = "https://www.virustotal.com/api/v3"
MALWAREBAZAAR_BASE = "https://mb-api.abuse.ch/api/v1"
URLSCAN_BASE = "https://urlscan.io/api/v1"

# ──────────────────────────────────────────────────────────────────
# Timeouts & Polling
# ──────────────────────────────────────────────────────────────────
REQUEST_TIMEOUT = 30
POLL_INTERVAL = 15
MAX_POLL_ATTEMPTS = 24       # 6 minutes total
MAX_FILE_SIZE_MB = 10
THREAD_POOL_WORKERS = 4

# ──────────────────────────────────────────────────────────────────
# Risk Model: API 60% / Static 40%
# ──────────────────────────────────────────────────────────────────
STATIC_WEIGHT = 0.40
API_WEIGHT = 0.60

# ──────────────────────────────────────────────────────────────────
# Suspicious Win32 APIs for IAT scanning
# ──────────────────────────────────────────────────────────────────
SUSPICIOUS_APIS = [
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
    "CreateRemoteThread", "NtCreateThreadEx",
    "WriteProcessMemory", "ReadProcessMemory", "OpenProcess",
    "CreateProcess", "WinExec", "ShellExecute",
    "URLDownloadToFile", "InternetOpen", "InternetOpenUrl",
    "HttpSendRequest", "HttpOpenRequest",
    "RegSetValueEx", "RegCreateKeyEx",
    "SetWindowsHookEx", "GetProcAddress",
    "LoadLibrary", "CryptEncrypt", "CryptDecrypt",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "AdjustTokenPrivileges", "LookupPrivilegeValue",
]

MALICIOUS_KEYWORDS = [
    "powershell", "cmd.exe", "wscript", "cscript", "mshta",
    "certutil", "bitsadmin", "regsvr32", "rundll32",
    "invoke-expression", "downloadstring", "bypass", "hidden",
    "mimikatz", "cobalt", "ransomware", "encrypt",
    "keylog", "screenshot", "webcam", "exfiltrat", "beacon",
]

# ──────────────────────────────────────────────────────────────────
# UI Theme (Flat Dark Utility)
# ──────────────────────────────────────────────────────────────────
THEME = {
    "bg":        "#0B0E14",
    "surface":   "#121620",
    "border":    "#2D3139",
    "accent":    "#00A3FF",
    "text":      "#E1E1E1",
    "muted":     "#6B7280",
    "danger":    "#EF4444",
    "warning":   "#F59E0B",
    "success":   "#10B981",
}
