"""
AI-Assisted Malware Behavior Analyzer — Main Dashboard
Flat, high-contrast dark mode. Professional utility interface.
"""
import json
import os
import re
import tempfile
from typing import Dict, Any, List

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from analysis_engine import AnalysisEngine
from api_clients import APIOrchestrator
from config import (
    HYBRID_ANALYSIS_API_KEY, VIRUSTOTAL_API_KEY, URLSCAN_API_KEY,
    STATIC_WEIGHT, API_WEIGHT, THEME,
)

# ──────────────────────────────────────────────────────────────────
# Page Config
# ──────────────────────────────────────────────────────────────────
st.set_page_config(page_title="MalScan", layout="wide")

# ──────────────────────────────────────────────────────────────────
# Flat Dark Mode CSS — CrowdStrike / SentinelOne inspired
# ──────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800;900&display=swap');
:root {
    --bg: #0B0E14; --surface: #121620; --border: #2D3139;
    --accent: #00A3FF; --text: #E1E1E1; --muted: #6B7280;
    --danger: #EF4444; --warning: #F59E0B; --success: #10B981;
}
.stApp, [data-testid="stAppViewContainer"], .main .block-container,
header[data-testid="stHeader"] { background-color: var(--bg) !important; }
[data-testid="stSidebar"] {
    background-color: var(--surface) !important;
    border-right: 1px solid var(--border) !important;
}
[data-testid="stSidebar"] * { color: var(--text) !important; }
h1,h2,h3,h4,h5,h6,p,span,label,li,td,th { color: var(--text) !important; }
hr { border-color: var(--border) !important; }
.stTabs [data-baseweb="tab-list"] {
    background: var(--surface) !important; border-bottom: 1px solid var(--border) !important;
    gap: 0 !important;
}
.stTabs [data-baseweb="tab"] {
    background: transparent !important; color: var(--muted) !important;
    border-bottom: 2px solid transparent !important; font-weight: 600 !important;
    padding: 10px 20px !important;
}
.stTabs [aria-selected="true"] {
    color: var(--accent) !important; border-bottom-color: var(--accent) !important;
}
.stTabs [data-baseweb="tab-highlight"], .stTabs [data-baseweb="tab-border"] { display: none !important; }
.stButton>button {
    background: var(--surface) !important; color: var(--accent) !important;
    border: 1px solid var(--border) !important; border-radius: 4px !important;
    font-weight: 600 !important;
}
.stButton>button:hover { border-color: var(--accent) !important; }
.stButton>button:active { background: var(--border) !important; }
[data-testid="stFileUploader"] {
    background: var(--surface) !important; border: 1px dashed var(--border) !important;
    border-radius: 4px !important;
}
[data-testid="stMetricValue"] { color: var(--accent) !important; font-size: 1.8rem !important; }
[data-testid="stMetricLabel"] {
    color: var(--muted) !important; text-transform: uppercase !important;
    letter-spacing: 0.08em !important; font-size: 0.7rem !important;
}
[data-testid="stExpander"], .stAlert, [data-testid="stForm"] {
    background: var(--surface) !important; border: 1px solid var(--border) !important;
    border-radius: 4px !important;
}
.stDownloadButton>button {
    background: var(--accent) !important; color: var(--bg) !important;
    border: none !important; font-weight: 700 !important; border-radius: 4px !important;
}
.stJson { background: var(--surface) !important; border-radius: 4px !important; }
.stMarkdown a { color: var(--accent) !important; }
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: var(--bg); }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
.hero-title { font-family: 'Outfit', sans-serif; font-size: 4rem; font-weight: 800; color: var(--text); letter-spacing: -0.02em; margin-bottom: 0 !important; }
.hero-sub { font-family: 'Outfit', sans-serif; font-size: 1.2rem; font-weight: 500; color: var(--muted); letter-spacing: 0.01em; margin-top: 0.2rem; margin-bottom: 2rem; }
.sidebar-title { font-family: 'Outfit', sans-serif; font-size: 1.6rem; font-weight: 700; color: var(--text); letter-spacing: -0.01em; margin-bottom: 0.5rem; }
.tool-header { font-size: 1.3rem; font-weight: 700; color: #E1E1E1; letter-spacing: -0.01em; }
.api-badge {
    display: inline-block; padding: 2px 8px; border-radius: 3px;
    font-size: 0.7rem; font-weight: 700; margin-right: 6px;
}
.badge-ok { background: #10B98120; color: #10B981; border: 1px solid #10B98140; }
.badge-off { background: #6B728020; color: #6B7280; border: 1px solid #6B728040; }
.badge-err { background: #EF444420; color: #EF4444; border: 1px solid #EF444440; }
</style>
""", unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────
def save_upload(uf) -> str:
    with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uf.name)[1]) as t:
        t.write(uf.getvalue())
        return t.name

def cleanup(p: str):
    try:
        if p and os.path.exists(p): os.remove(p)
    except OSError: pass

def urls_from_strings(s: dict) -> list:
    return list(set(re.findall(r"https?://[^\s\"'<>]+", " ".join(s.get("Network", [])))))[:10]

def risk_score(static: Dict, api_results: Dict) -> Dict[str, Any]:
    ss = 0
    rules = []
    if static.get("is_packed"):
        ss += 15; rules.append(f"High entropy ({static['entropy']:.2f})")
    secs = static.get("binary", {}).get("sections", [])
    packed = [s for s in secs if s.get("suspicious")]
    if packed:
        ss += min(len(packed) * 20, 60)
        rules.append(f"{len(packed)} high-entropy section(s)")
    sus = static.get("binary", {}).get("suspicious_imports", [])
    if sus:
        ss += min(len(sus) * 10, 50)
        rules.append(f"{len(sus)} suspicious API import(s)")
    net = static.get("strings", {}).get("Network", [])
    if net:
        ss += min(len(net) * 5, 20); rules.append(f"{len(net)} network indicator(s)")
    mal = static.get("strings", {}).get("Malicious", [])
    if mal:
        ss += min(len(mal) * 8, 40); rules.append(f"{len(mal)} malicious keyword(s)")
    ss = min(ss, 100)

    api_s = 0
    vt = api_results.get("virustotal", {})
    if vt.get("status") == "SUCCESS":
        m = vt["data"].get("malicious", 0)
        if m > 5: api_s += 50; rules.append(f"VT: {vt['data'].get('detection_ratio')} detections")
        elif m > 0: api_s += 25; rules.append(f"VT: low-confidence ({m} engines)")
    ha = api_results.get("hybrid_analysis", {})
    if ha.get("status") == "SUCCESS":
        v = ha["data"].get("verdict", "")
        if v == "malicious": api_s += 50; rules.append(f"HA: malicious verdict")
        elif v == "suspicious": api_s += 25; rules.append(f"HA: suspicious verdict")
    mb = api_results.get("malwarebazaar", {})
    if mb.get("status") == "SUCCESS":
        f = mb["data"].get("family", "Unknown")
        api_s += 40; rules.append(f"MalwareBazaar: family={f}")
    api_s = min(api_s, 100)

    final = int(ss * STATIC_WEIGHT + api_s * API_WEIGHT)
    final = min(max(final, 0), 100)
    level = "CRITICAL" if final > 75 else "HIGH" if final > 50 else "MEDIUM" if final > 20 else "LOW"
    return {"score": final, "level": level, "static_score": ss, "api_score": api_s, "rules": rules}

def predictions(static: Dict, api_results: Dict) -> List[str]:
    preds = []
    funcs = {i.get("pattern","").lower() for i in static.get("binary",{}).get("suspicious_imports",[])}
    if any("createremotethread" in f or "writeprocessmemory" in f for f in funcs):
        preds.append("🔴 Process injection capability detected")
    if any("virtualalloc" in f for f in funcs):
        preds.append("🟡 Executable memory allocation (shellcode staging)")
    if any("urldownloadtofile" in f or "internetopen" in f for f in funcs):
        preds.append("🔴 Remote payload download capability")
    if any("regsetvalue" in f or "regcreatekey" in f for f in funcs):
        preds.append("🟡 Registry modification (persistence)")
    if any("setwindowshookex" in f for f in funcs):
        preds.append("🔴 Input hooking (keylogger)")
    if any("isdebuggerpresent" in f for f in funcs):
        preds.append("🟡 Anti-debugging techniques")
    if any("cryptencrypt" in f for f in funcs):
        preds.append("🟡 Cryptographic operations")
    if any("adjusttokenprivileges" in f for f in funcs):
        preds.append("🔴 Privilege escalation attempt")
    net = static.get("strings",{}).get("Network",[])
    if net: preds.append(f"🔴 {len(net)} external network endpoint(s)")
    mal = " ".join(static.get("strings",{}).get("Malicious",[])).lower()
    if any(k in mal for k in ["ransomware","encrypt","bitcoin"]): preds.append("🔴 Ransomware indicators")
    if any(k in mal for k in ["keylog","screenshot","webcam"]): preds.append("🔴 Spyware indicators")
    mb = api_results.get("malwarebazaar",{})
    if mb.get("status") == "SUCCESS":
        f = mb["data"].get("family","")
        if f and f != "Unknown": preds.append(f"🔴 Known malware family: {f}")
    if static.get("is_packed"): preds.append("🟡 File is packed/encrypted")
    if not preds: preds.append("🟢 No strong threat indicators")
    return preds

def make_gauge(score: int, level: str) -> go.Figure:
    cmap = {"LOW": THEME["success"], "MEDIUM": THEME["warning"], "HIGH": THEME["danger"], "CRITICAL": "#FF0040"}
    c = cmap.get(level, THEME["accent"])
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=score,
        number={"font": {"size": 48, "color": THEME["text"]}, "suffix": "/100"},
        title={"text": level, "font": {"size": 14, "color": c}},
        gauge={"axis": {"range": [0,100], "tickcolor": THEME["muted"]},
               "bar": {"color": c, "thickness": 0.65},
               "bgcolor": THEME["surface"], "bordercolor": THEME["border"],
               "steps": [{"range":[0,20],"color":"rgba(16,185,129,0.06)"},{"range":[20,50],"color":"rgba(245,158,11,0.06)"},
                         {"range":[50,75],"color":"rgba(239,68,68,0.08)"},{"range":[75,100],"color":"rgba(255,0,64,0.12)"}]},
    ))
    fig.update_layout(paper_bgcolor=THEME["bg"], plot_bgcolor=THEME["bg"],
                      height=250, margin=dict(l=25,r=25,t=50,b=20))
    return fig

def badge(status: str) -> str:
    if status == "SUCCESS": return '<span class="api-badge badge-ok">ONLINE</span>'
    if status in ("SKIPPED",): return '<span class="api-badge badge-off">SKIPPED</span>'
    return f'<span class="api-badge badge-err">{status}</span>'

def export_json(static: Dict, api_results: Dict, risk: Dict) -> str:
    out = {"risk": risk, "static": {k:v for k,v in static.items() if k != "entropy_heatmap"}, "api": api_results}
    return json.dumps(out, indent=2, default=str)

def export_txt(static: Dict, risk: Dict, preds: List[str]) -> str:
    h = static["hashes"]
    m = static["metadata"]
    lines = [
        "=" * 60, "  AI-ASSISTED MALWARE BEHAVIOR ANALYZER — REPORT", "=" * 60, "",
        f"  File:      {m['filename']}", f"  Size:      {m['size_human']}",
        f"  SHA-256:   {h['sha256']}", f"  Type:      {static['file_type']}",
        f"  Entropy:   {static['entropy']:.4f}", "",
        "-" * 60,
        f"  RISK: {risk['score']}/100 ({risk['level']})",
        f"  Static: {risk['static_score']}/100 | API: {risk['api_score']}/100",
        "-" * 60, "", "  PREDICTIONS:",
    ]
    for p in preds: lines.append(f"    {p}")
    lines += ["", "  RULES:"]
    for r in risk["rules"]: lines.append(f"    • {r}")
    lines += ["", "=" * 60]
    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────
# Sidebar
# ──────────────────────────────────────────────────────────────────
st.sidebar.markdown('<p class="sidebar-title">Analysis control panel</p>', unsafe_allow_html=True)
st.sidebar.markdown("---")

uploaded = st.sidebar.file_uploader("Upload file for analysis",
    type=["exe","dll","elf","so","py","js","sh","bat","ps1","doc","xls","pdf","zip"])
use_apis = st.sidebar.checkbox("Enable API Intelligence", value=True)
if st.sidebar.button("🔄 Reset"):
    st.rerun()

st.sidebar.markdown("---")

# API status badges
def key_badge(name: str, key: str) -> str:
    if key and key.strip():
        return f'<span class="api-badge badge-ok">✓</span> {name}'
    return f'<span class="api-badge badge-off">—</span> {name}'

st.sidebar.markdown(key_badge("Hybrid Analysis", HYBRID_ANALYSIS_API_KEY), unsafe_allow_html=True)
st.sidebar.markdown(key_badge("VirusTotal", VIRUSTOTAL_API_KEY), unsafe_allow_html=True)
st.sidebar.markdown('<span class="api-badge badge-ok">✓</span> MalwareBazaar (free)', unsafe_allow_html=True)
st.sidebar.markdown(key_badge("URLScan.io", URLSCAN_API_KEY), unsafe_allow_html=True)

st.sidebar.markdown("---")
st.sidebar.caption("Files are deleted from temp after analysis. Local static analysis only — no malware execution on host.")


# ──────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────
st.markdown('<p class="hero-title">MalScan</p>', unsafe_allow_html=True)
st.markdown('<p class="hero-sub">AI-Assisted Malware Behavior Analyzer</p>', unsafe_allow_html=True)

if uploaded:
    path = save_upload(uploaded)
    try:
        with st.status("Running analysis pipeline...", expanded=True) as status:
            st.write("▸ Static analysis engine...")
            engine = AnalysisEngine(path)
            static = engine.run()
            st.write(f"  Type: **{static['file_type']}** | Entropy: **{static['entropy']:.4f}** | Packed: **{'Yes' if static['is_packed'] else 'No'}**")

            api_results: Dict[str, Dict[str, Any]] = {}
            consensus = {}
            if use_apis:
                st.write("▸ Querying APIs (concurrent)...")
                urls = urls_from_strings(static.get("strings", {}))
                orch = APIOrchestrator(static["hashes"]["sha256"], urls)
                api_results = orch.run_all()
                consensus = orch.compute_consensus(api_results)
                st.write(f"  Sources: **{consensus['queried']}** queried, **{consensus['flagged']}** flagged")

            st.write("▸ Computing risk assessment...")
            risk = risk_score(static, api_results)
            preds = predictions(static, api_results)
            status.update(label="✅ Analysis complete", state="complete", expanded=False)

        # ── Tabs ──────────────────────────────────────────────────
        t1, t2, t3, t4, t5 = st.tabs(["Dashboard", "Static Analysis", "Intelligence", "Predictions", "Export"])

        with t1:
            c1, c2 = st.columns([1, 1])
            with c1:
                st.plotly_chart(make_gauge(risk["score"], risk["level"]), use_container_width=True)
            with c2:
                m = static["metadata"]; h = static["hashes"]
                st.markdown(f"""
| | |
|---|---|
| **File** | `{m['filename']}` |
| **Size** | {m['size_human']} |
| **Type** | {static['file_type']} |
| **SHA-256** | `{h['sha256'][:40]}...` |
| **Entropy** | {static['entropy']:.4f} {'⚠️' if static['is_packed'] else '✓'} |
| **Static Score** | {risk['static_score']}/100 |
| **API Score** | {risk['api_score']}/100 |
""")
                if consensus:
                    st.markdown(f"**Consensus:** {consensus['label']} ({consensus['confidence']})")
                    if consensus.get("families"):
                        st.error(f"Identified family: **{', '.join(consensus['families'])}**")

            st.markdown("---")
            st.markdown("**Triggered Rules**")
            for r in risk["rules"]:
                st.info(f"• {r}")

        with t2:
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**Hashes**")
                st.json(static["hashes"])
            with c2:
                st.metric("Entropy", f"{static['entropy']:.4f}")
                st.write("Packed:", "⚠️ Yes" if static["is_packed"] else "✓ No")

            if static.get("entropy_heatmap"):
                st.markdown("**Entropy Heatmap**")
                st.plotly_chart(static["entropy_heatmap"], use_container_width=True)

            bi = static.get("binary", {})
            if bi.get("type") in ("PE", "ELF"):
                st.markdown(f"**Binary: {bi['type']}**")
                if bi.get("entry_point"):
                    st.write(f"Entry Point: `{bi['entry_point']}`")
                secs = bi.get("sections", [])
                if secs:
                    st.markdown("*Sections*")
                    st.dataframe(pd.DataFrame(secs), use_container_width=True)
                sus = bi.get("suspicious_imports", [])
                if sus:
                    st.warning(f"**{len(sus)}** suspicious API import(s)")
                    st.dataframe(pd.DataFrame(sus), use_container_width=True)
                exp = bi.get("exports", [])
                if exp:
                    st.markdown("*Export Table*")
                    st.dataframe(pd.DataFrame(exp), use_container_width=True)

            strings = static.get("strings", {})
            if any(strings.values()):
                st.markdown("**Strings**")
                s1,s2,s3,s4 = st.tabs(["Network","Paths","Commands","Malicious"])
                with s1: st.write(strings.get("Network") or "None")
                with s2: st.write(strings.get("Paths") or "None")
                with s3: st.write(strings.get("Commands") or "None")
                with s4: st.write(strings.get("Malicious") or "None")

        with t3:
            if not use_apis or not api_results:
                st.info("API intelligence disabled. Enable in sidebar.")
            else:
                for key, label in [("hybrid_analysis","Hybrid Analysis"),("virustotal","VirusTotal"),
                                   ("malwarebazaar","MalwareBazaar"),("urlscan","URLScan.io")]:
                    r = api_results.get(key, {})
                    st.markdown(f"**{label}** {badge(r.get('status','SKIPPED'))}", unsafe_allow_html=True)
                    if r.get("status") == "SUCCESS":
                        d = r["data"]
                        if key == "virustotal":
                            c1,c2,c3 = st.columns(3)
                            c1.metric("Detection", d.get("detection_ratio","N/A"))
                            c2.metric("Reputation", d.get("reputation","N/A"))
                            c3.metric("Type", d.get("type_description","N/A"))
                            vv = d.get("vendor_verdicts",[])
                            if vv: st.dataframe(pd.DataFrame(vv), use_container_width=True)
                        elif key == "hybrid_analysis":
                            c1,c2 = st.columns(2)
                            c1.metric("Verdict", d.get("verdict","N/A"))
                            c2.metric("Threat Score", d.get("threat_score","N/A"))
                            if d.get("vx_family"): st.write(f"Family: **{d['vx_family']}**")
                            if d.get("mitre_attcks"):
                                st.markdown("*MITRE ATT&CK*")
                                st.dataframe(pd.DataFrame(d["mitre_attcks"]), use_container_width=True)
                        elif key == "malwarebazaar":
                            c1,c2 = st.columns(2)
                            c1.metric("Family", d.get("family","N/A"))
                            c2.metric("Delivery", d.get("delivery","N/A"))
                            st.write(f"First seen: {d.get('first_seen','N/A')}")
                        elif key == "urlscan":
                            ul = d.get("results",[])
                            if ul: st.dataframe(pd.DataFrame(ul), use_container_width=True)
                    elif r.get("error"):
                        st.caption(r["error"])
                    st.markdown("---")

        with t4:
            st.markdown("**Behavioral Predictions**")
            for p in preds:
                st.markdown(f"**{p}**")
            st.markdown("---")
            c1, c2 = st.columns(2)
            c1.metric("Static Score", f"{risk['static_score']}/100")
            c2.metric("API Score", f"{risk['api_score']}/100")

        with t5:
            c1, c2 = st.columns(2)
            with c1:
                st.download_button("⬇ JSON Report", export_json(static, api_results, risk),
                    f"report_{static['hashes']['sha256'][:8]}.json", "application/json")
            with c2:
                st.download_button("⬇ TXT Report", export_txt(static, risk, preds),
                    f"report_{static['hashes']['sha256'][:8]}.txt", "text/plain")
            st.markdown("---")
            st.json(json.loads(export_json(static, api_results, risk)))
    finally:
        cleanup(path)
else:
    st.markdown("---")
    c1, c2 = st.columns([2,1])
    with c1:
        st.markdown("""
### Upload a file to begin analysis

| Engine | Capability |
|--------|-----------|
| **PE Parser** | IAT imports, Export Table, sections, entry point |
| **ELF Parser** | Headers, sections, entry point |
| **Entropy** | Shannon entropy + visual heatmap |
| **Strings** | URLs, IPs, paths, commands, malicious keywords |
| **Hybrid Analysis** | Cloud sandbox — full behavioral report |
| **VirusTotal v3** | AV detection consensus |
| **MalwareBazaar** | Known malware family identification |
| **URLScan.io** | Extracted URL reputation |
""")
    with c2:
        st.metric("API Engines", "4")
        st.metric("Static Checks", "7+")
        st.metric("Risk Model", "60/40")
