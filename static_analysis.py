import hashlib
import math
import re
import os
import pefile
from elftools.elf.elffile import ELFFile
from typing import Dict, List, Any, Optional

class StaticAnalyzer:
    """
    Engine for static malware analysis.
    Performs hashing, entropy calculation, string extraction, and binary parsing.
    """

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.file_name = os.path.basename(file_path)
        self.file_size = os.path.getsize(file_path)
        with open(file_path, "rb") as f:
            self.data = f.read()

    def get_metadata(self) -> Dict[str, Any]:
        return {
            "filename": self.file_name,
            "size_bytes": self.file_size,
            "extension": os.path.splitext(self.file_name)[1].lower(),
        }

    def get_hashes(self) -> Dict[str, str]:
        return {
            "md5": hashlib.md5(self.data).hexdigest(),
            "sha1": hashlib.sha1(self.data).hexdigest(),
            "sha256": hashlib.sha256(self.data).hexdigest(),
        }

    def calculate_entropy(self) -> float:
        """Calculate Shannon entropy of the file data."""
        if not self.data:
            return 0.0
        entropy = 0
        for x in range(256):
            p_x = float(self.data.count(x)) / len(self.data)
            if p_x > 0:
                entropy += -p_x * math.log(p_x, 2)
        return round(entropy, 4)

    def extract_strings(self, min_len: int = 4) -> Dict[str, List[str]]:
        """Extract ASCII strings and categorize them using regex."""
        # Regex for ASCII strings
        pattern = re.compile(rb"[\x20-\x7E]{" + str(min_len).encode() + rb",}")
        found_strings = [s.decode('ascii', errors='ignore') for s in pattern.findall(self.data)]

        categories = {
            "Network": [],
            "Paths": [],
            "Commands": [],
            "Malicious": [],
            "Other": []
        }

        patterns = {
            "Network": r"(http|https|ftp)://|(\d{1,3}\.){3}\d{1,3}|[a-zA-Z0-9.-]+\.(com|net|org|io|biz|info|ru|cn)",
            "Paths": r"([a-zA-Z]:\\|/etc/|/tmp/|/var/|/usr/|AppData|Temp|System32)",
            "Commands": r"(powershell|cmd\.exe|netsh|schtasks|curl|wget|taskkill|bash|sh|at\s|reg\s|sc\s)",
            "Malicious": r"(inject|kill|encrypt|decrypt|backdoor|malware|ransomware|persistence|autostart|keylogger|stealer|c2|payload|base64|eval|char\()",
        }

        for s in found_strings:
            matched = False
            for cat, regex in patterns.items():
                if re.search(regex, s, re.IGNORECASE):
                    categories[cat].append(s)
                    matched = True
            if not matched:
                categories["Other"].append(s)

        # Deduplicate and limit
        for cat in categories:
            categories[cat] = list(set(categories[cat]))[:100]  # Limit to 100 per cat for display

        return categories

    def analyze_binary(self) -> Dict[str, Any]:
        """Parse PE or ELF headers to extract imports."""
        results = {"type": "Unknown", "imports": [], "suspicious_imports": []}
        
        # PE Analysis
        try:
            pe = pefile.PE(data=self.data)
            results["type"] = "Windows PE"
            suspicious_apis = {
                "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", 
                "RegSetValueEx", "SetWindowsHookEx", "CryptAcquireContext",
                "InternetOpen", "HttpSendRequest", "ShellExecute", "WinExec"
            }
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        name = imp.name.decode() if imp.name else ""
                        results["imports"].append(name)
                        if any(api in name for api in suspicious_apis):
                            results["suspicious_imports"].append(name)
            return results
        except Exception:
            pass

        # ELF Analysis
        try:
            with open(self.file_path, "rb") as f:
                elf = ELFFile(f)
                results["type"] = "Linux ELF"
                # Basic ELF analysis could be added here
            return results
        except Exception:
            pass

        return results

    def run_analysis(self) -> Dict[str, Any]:
        """Orchestrate all static analysis tasks."""
        entropy = self.calculate_entropy()
        return {
            "metadata": self.get_metadata(),
            "hashes": self.get_hashes(),
            "entropy": entropy,
            "is_packed": entropy >= 7.5,
            "strings": self.extract_strings(),
            "binary_info": self.analyze_binary()
        }
