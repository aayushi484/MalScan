"""
AI-Assisted Malware Behavior Analyzer — Static Analysis Engine
PE IAT/Export extraction, ELF parsing, Shannon entropy, categorized strings.
"""
import hashlib
import math
import os
import re
from typing import Any, Dict, List, Optional

import plotly.graph_objects as go

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    from elftools.elf.elffile import ELFFile
    HAS_ELFTOOLS = True
except ImportError:
    HAS_ELFTOOLS = False

from config import SUSPICIOUS_APIS, MALICIOUS_KEYWORDS, MAX_FILE_SIZE_MB, THEME


def compute_hashes(path: str) -> Dict[str, str]:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            md5.update(chunk); sha1.update(chunk); sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    return round(-sum((c / length) * math.log2(c / length) for c in freq if c), 4)


def detect_type(path: str) -> str:
    with open(path, "rb") as f:
        h = f.read(4)
    if h[:2] == b"MZ":
        return "PE"
    if h[:4] == b"\x7fELF":
        return "ELF"
    return "UNKNOWN"


def analyze_pe(path: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "format": "PE", "sections": [], "imports": [],
        "exports": [], "suspicious_imports": [],
        "entry_point": None, "compile_time": None, "error": None,
    }
    if not HAS_PEFILE:
        result["error"] = "pefile not installed"
        return result
    try:
        pe = pefile.PE(path)
    except pefile.PEFormatError as e:
        result["error"] = str(e)
        return result

    result["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    result["compile_time"] = pe.FILE_HEADER.TimeDateStamp

    # Sections
    for s in pe.sections:
        name = s.Name.decode("utf-8", errors="replace").strip("\x00")
        ent = shannon_entropy(s.get_data())
        result["sections"].append({
            "name": name, "virtual_size": s.Misc_VirtualSize,
            "raw_size": s.SizeOfRawData, "entropy": ent,
            "suspicious": ent > 7.0,
        })

    # IAT
    suspicious = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("utf-8", errors="replace")
            for imp in entry.imports:
                fn = imp.name.decode("utf-8", errors="replace") if imp.name else f"ord_{imp.ordinal}"
                result["imports"].append({"dll": dll, "function": fn})
                for sus in SUSPICIOUS_APIS:
                    if sus.lower() in fn.lower():
                        suspicious.append({"dll": dll, "function": fn, "pattern": sus})
                        break
    result["suspicious_imports"] = suspicious

    # Export Table
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode("utf-8", errors="replace") if exp.name else f"ord_{exp.ordinal}"
            result["exports"].append({"name": name, "ordinal": exp.ordinal, "address": hex(exp.address)})

    pe.close()
    return result


def analyze_elf(path: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "format": "ELF", "sections": [], "machine": None,
        "entry_point": None, "elf_class": None, "error": None,
    }
    if not HAS_ELFTOOLS:
        result["error"] = "pyelftools not installed"
        return result
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            result["machine"] = elf.header.e_machine
            result["entry_point"] = hex(elf.header.e_entry)
            result["elf_class"] = elf.elfclass
            for sec in elf.iter_sections():
                d = sec.data()
                ent = shannon_entropy(d) if d else 0.0
                result["sections"].append({
                    "name": sec.name, "type": sec["sh_type"],
                    "size": sec["sh_size"], "entropy": ent,
                    "suspicious": ent > 7.0,
                })
    except Exception as e:
        result["error"] = str(e)
    return result


def extract_strings(path: str, min_len: int = 5) -> Dict[str, List[str]]:
    cats: Dict[str, List[str]] = {"Network": [], "Paths": [], "Commands": [], "Malicious": []}
    with open(path, "rb") as f:
        data = f.read()
    raw = re.findall(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}", data)
    seen = set()
    for r in raw:
        s = r.decode("ascii", errors="replace")
        if s in seen:
            continue
        seen.add(s)
        lo = s.lower()
        if re.search(r"https?://", s) or re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", s):
            cats["Network"].append(s); continue
        if re.search(r"(?:[A-Z]:\\|/(?:usr|etc|tmp|var|home|Windows))", s, re.I) or re.search(r"HK(?:LM|CU)", s, re.I):
            cats["Paths"].append(s); continue
        if any(k in lo for k in MALICIOUS_KEYWORDS):
            cats["Malicious"].append(s); continue
        if any(c in lo for c in ["cmd", "powershell", "bash", "/bin/", "exec"]):
            cats["Commands"].append(s); continue
    return cats


def generate_entropy_heatmap(path: str, chunk_size: int = 256) -> Optional[go.Figure]:
    with open(path, "rb") as f:
        data = f.read()
    entropies = [shannon_entropy(data[i:i+chunk_size]) for i in range(0, len(data), chunk_size)]
    if not entropies:
        return None
    cols = 64
    rows = math.ceil(len(entropies) / cols)
    padded = entropies + [0.0] * (rows * cols - len(entropies))
    grid = [padded[i*cols:(i+1)*cols] for i in range(rows)]

    fig = go.Figure(go.Heatmap(
        z=grid, zmin=0, zmax=8,
        colorscale=[[0, "#0B0E14"], [0.4, "#121620"], [0.7, "#00A3FF"], [0.88, "#F59E0B"], [1, "#EF4444"]],
        colorbar=dict(title="Entropy", tickvals=[0,2,4,6,7,8],
                      ticktext=["0","2","4","6","7 (sus)","8 (rand)"]),
        hovertemplate="Offset: %{x}×" + str(chunk_size) + "B<br>Entropy: %{z:.2f}<extra></extra>",
    ))
    fig.update_layout(
        paper_bgcolor=THEME["bg"], plot_bgcolor=THEME["bg"],
        xaxis=dict(title="Chunk", color=THEME["muted"], showgrid=False),
        yaxis=dict(title="Block", color=THEME["muted"], showgrid=False, autorange="reversed"),
        margin=dict(l=50, r=20, t=30, b=30), height=max(180, rows * 6),
    )
    return fig


class AnalysisEngine:
    def __init__(self, path: str):
        self.path = path
        self.size = os.path.getsize(path)
        self.name = os.path.basename(path)
        self.oversized = self.size > MAX_FILE_SIZE_MB * 1024 * 1024

    def run(self) -> Dict[str, Any]:
        hashes = compute_hashes(self.path)
        ftype = detect_type(self.path)
        with open(self.path, "rb") as f:
            raw = f.read()
        ent = shannon_entropy(raw)

        binary = {"type": ftype}
        if not self.oversized:
            if ftype == "PE":
                binary.update(analyze_pe(self.path))
            elif ftype == "ELF":
                binary.update(analyze_elf(self.path))
        else:
            binary["skipped"] = "File exceeds size limit"

        strings = extract_strings(self.path) if not self.oversized else {k: [] for k in ["Network","Paths","Commands","Malicious"]}
        heatmap = generate_entropy_heatmap(self.path) if not self.oversized else None

        return {
            "metadata": {"filename": self.name, "size_bytes": self.size,
                         "size_human": self._human(self.size), "oversized": self.oversized},
            "hashes": hashes, "file_type": ftype, "entropy": ent,
            "is_packed": ent > 7.5, "binary": binary,
            "strings": strings, "entropy_heatmap": heatmap,
        }

    @staticmethod
    def _human(b: int) -> str:
        for u in ["B","KB","MB","GB"]:
            if b < 1024: return f"{b:.1f} {u}"
            b /= 1024
        return f"{b:.1f} TB"
