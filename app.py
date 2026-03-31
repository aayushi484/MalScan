import streamlit as st
import os
import tempfile
import json
from static_analysis import StaticAnalyzer
from sandbox_api_client import SandboxClient
from report_engine import ReportEngine
from config import API_KEY

# Page Configuration
st.set_page_config(
    page_title="AI-Assisted Malware Behavior Analyzer",
    page_icon="🛡️",
    layout="wide"
)

# Custom Styling
st.markdown("""
<style>
    .stProgress .st-bo { background-color: #f63366; }
    .risk-low { color: #28a745; font-weight: bold; }
    .risk-medium { color: #ffc107; font-weight: bold; }
    .risk-high { color: #dc3545; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

# Helper functions
def save_uploaded_file(uploaded_file):
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded_file.name)[1]) as tmp_file:
            tmp_file.write(uploaded_file.getvalue())
            return tmp_file.name
    except Exception as e:
        st.error(f"Error saving file: {e}")
        return None

def get_risk_color(level):
    if level == "LOW": return "green"
    if level == "MEDIUM": return "orange"
    if level == "HIGH": return "red"
    return "grey"

# Sidebar
st.sidebar.title("Analyzer Controls")
uploaded_file = st.sidebar.file_uploader(
    "Upload suspicious file", 
    type=['exe', 'dll', 'elf', 'so', 'py', 'js', 'sh', 'bat', 'ps1']
)

dynamic_enabled = st.sidebar.checkbox("Enable Dynamic Analysis (Sandbox API)")

if st.sidebar.button("Reset / Analyze another file"):
    st.rerun()

st.sidebar.info(
    "**Note:** Dynamic analysis is performed off-host via the Hybrid Analysis API. "
    "This tool is for educational use only. Never execute malware on your host machine."
)

if not API_KEY or "YOUR_API_KEY" in API_KEY:
    st.sidebar.warning("⚠️ Hybrid Analysis API Key not set in config.py or env.")

# Main Dashboard
st.title("AI-Assisted Malware Behavior Analyzer")
st.markdown("### Static + Sandbox-based Dynamic Analysis")

if uploaded_file:
    file_path = save_uploaded_file(uploaded_file)
    
    if file_path:
        with st.status("Performing Analysis...", expanded=True) as status:
            # 1. Static Analysis
            st.write("Running static analysis engine...")
            analyzer = StaticAnalyzer(file_path)
            static_results = analyzer.run_analysis()
            
            # 2. Dynamic Analysis
            dynamic_results = None
            if dynamic_enabled:
                if not API_KEY or "YOUR_API_KEY" in API_KEY:
                    st.error("API Key missing! Skipping dynamic analysis.")
                else:
                    st.write("Submitting to Sandbox API (this may take a few minutes)...")
                    client = SandboxClient()
                    dynamic_results = client.get_full_report(file_path)
            
            # 3. Combined Reporting
            st.write("Synthesizing final report...")
            engine = ReportEngine(static_results, dynamic_results)
            full_report = engine.generate_full_report()
            status.update(label="Analysis Complete!", state="complete", expanded=False)

        # Tabs for Visualization
        tab1, tab2, tab3, tab4 = st.tabs(["Summary", "Static Analysis", "Dynamic Report", "Export Report"])

        with tab1:
            col1, col2 = st.columns([1, 2])
            with col1:
                risk_level = full_report['summary']['risk_level']
                risk_score = full_report['summary']['risk_score']
                st.metric("Risk Score", f"{risk_score}/100")
                st.markdown(f"**Threat Level:** :{get_risk_color(risk_level)}[{risk_level}]")
            
            with col2:
                st.subheader("Likely Behaviors")
                for pred in full_report['summary']['predictions']:
                    st.write(f"- {pred}")
            
            st.divider()
            st.subheader("Analysis Breakdown")
            for rule in full_report['summary']['triggered_rules']:
                st.info(f"💡 {rule}")

        with tab2:
            st.subheader("File Metadata")
            st.table(full_report['static_analysis']['metadata'])
            
            st.subheader("Cryptographic Hashes")
            st.json(full_report['static_analysis']['hashes'])
            
            col_e1, col_e2 = st.columns(2)
            with col_e1:
                st.metric("Shannon Entropy", full_report['static_analysis']['entropy'])
            with col_e2:
                st.write("**Packed/Obfuscated:**", "✅ Yes" if full_report['static_analysis']['is_packed'] else "❌ No")
            
            st.subheader("Binary Imports & APIs")
            bin_info = full_report['static_analysis']['binary_info']
            st.write(f"**Format:** {bin_info['type']}")
            if bin_info['suspicious_imports']:
                st.warning(f"Detected {len(bin_info['suspicious_imports'])} suspicious APIs:")
                st.dataframe(bin_info['suspicious_imports'], use_container_width=True)
            
            st.subheader("Categorized Strings")
            cat_strings = full_report['static_analysis']['strings']
            s_tab1, s_tab2, s_tab3, s_tab4 = st.tabs(["Network", "Paths", "Commands", "Malicious Keywords"])
            with s_tab1: st.write(cat_strings['Network'] or "No indicators found.")
            with s_tab2: st.write(cat_strings['Paths'] or "No indicators found.")
            with s_tab3: st.write(cat_strings['Commands'] or "No indicators found.")
            with s_tab4: st.write(cat_strings['Malicious'] or "No indicators found.")

        with tab3:
            if not dynamic_enabled:
                st.info("Dynamic analysis was not enabled for this scan.")
            elif dynamic_results and dynamic_results.get("status") == "SUCCESS":
                data = dynamic_results['data']
                st.success(f"Dynamic report retrieved from: {dynamic_results['source']}")
                
                col_d1, col_d2 = st.columns(2)
                with col_d1:
                    st.metric("Sandbox Threat Score", f"{data.get('threat_score', 0)}/100")
                with col_d2:
                    st.write("**Sandbox Verdict:**", data.get('verdict', 'N/A').upper())
                
                if data.get('mitre_attcks'):
                    st.subheader("MITRE ATT&CK Techniques")
                    st.dataframe(data['mitre_attcks'], use_container_width=True)
                
                if data.get('network_info'):
                    st.subheader("Network Activity")
                    st.json(data['network_info'])
            else:
                st.error(f"Dynamic Analysis Failed: {dynamic_results.get('error', 'Unknown Error')}")

        with tab4:
            st.subheader("Download Structured Report")
            json_report = json.dumps(full_report, indent=4)
            st.download_button(
                label="Download JSON Report",
                data=json_report,
                file_name=f"malware_report_{full_report['static_analysis']['hashes']['sha256'][:8]}.json",
                mime="application/json"
            )
            
            # Simple TXT generation
            txt_report = f"MALWARE ANALYSIS REPORT\n{'='*25}\n"
            txt_report += f"File: {full_report['static_analysis']['metadata']['filename']}\n"
            txt_report += f"Risk Score: {full_report['summary']['risk_score']}/100 ({full_report['summary']['risk_level']})\n\n"
            txt_report += "BEHAVIORAL PREDICTIONS:\n"
            for p in full_report['summary']['predictions']: txt_report += f"- {p}\n"
            
            st.download_button(
                label="Download TXT Report",
                data=txt_report,
                file_name=f"malware_report_{full_report['static_analysis']['hashes']['sha256'][:8]}.txt",
                mime="text/plain"
            )

        # Cleanup
        try:
            os.remove(file_path)
        except:
            pass

else:
    st.info("Please upload a file in the sidebar to begin analysis.")
