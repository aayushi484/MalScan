from typing import Dict, List, Any
from config import WEIGHTS, RISK_LEVELS

class ReportEngine:
    """
    Synthesizes static and dynamic analysis results into a unified report.
    Calculates risk scores and generates behavioral predictions.
    """

    def __init__(self, static_results: Dict[str, Any], dynamic_results: Dict[str, Any] = None):
        self.static = static_results
        self.dynamic = dynamic_results or {}
        self.score = 0
        self.triggered_rules = []
        self.predictions = []

    def calculate_score(self) -> int:
        """Calculate combined risk score based on static and dynamic indicators."""
        score = 0
        
        # 1. Static Scoring
        if self.static.get("is_packed"):
            score += WEIGHTS["packed"]
            self.triggered_rules.append("High entropy/possible packing detected.")
        elif self.static.get("entropy", 0) > 6.5:
            score += WEIGHTS["high_entropy"]
            self.triggered_rules.append("Moderate to high entropy observed.")

        suspicious_imps = self.static.get("binary_info", {}).get("suspicious_imports", [])
        if suspicious_imps:
            score += len(suspicious_imps) * WEIGHTS["suspicious_import"]
            self.triggered_rules.append(f"{len(suspicious_imps)} suspicious system APIs found in IAT.")

        strings = self.static.get("strings", {})
        if strings.get("Network"):
            score += WEIGHTS["network_string"]
            self.triggered_rules.append("Hardcoded network indicators (IPs/URLs) found.")
        if strings.get("Persistence"):
            score += WEIGHTS["persistence_string"]
            self.triggered_rules.append("Persistence mechanisms (Registry/Autostart) referenced in strings.")
        if strings.get("Malicious"):
            score += WEIGHTS["malicious_keyword"]
            self.triggered_rules.append("Malicious keywords (inject, crypt, backdoor) detected.")

        # 2. Dynamic Scoring (if available)
        if self.dynamic.get("status") == "SUCCESS":
            data = self.dynamic.get("data", {})
            threat_score = data.get("threat_score", 0)
            verdict = data.get("verdict", "").lower()

            if verdict == "malicious":
                score += WEIGHTS["dynamic_malicious_verdict"]
                self.triggered_rules.append("Sandbox API labeled the file as Malicious.")
            elif verdict == "suspicious":
                score += WEIGHTS["dynamic_suspicious_verdict"]
                self.triggered_rules.append("Sandbox API labeled the file as Suspicious.")

            # Additional dynamic indicators
            if data.get("network_info", {}).get("hosts"):
                score += WEIGHTS["dynamic_network_activity"]
                self.triggered_rules.append("Observed active network communication in sandbox.")

        self.score = min(score, 100)  # Cap at 100
        return self.score

    def generate_predictions(self) -> List[str]:
        """Generate human-readable behavioral predictions."""
        predictions = []
        
        # Static markers
        suspicious_imps = self.static.get("binary_info", {}).get("suspicious_imports", [])
        if any(x in str(suspicious_imps) for x in ["CreateRemoteThread", "WriteProcessMemory"]):
            predictions.append("Likely attempts process injection or memory manipulation.")
        if any(x in str(suspicious_imps) for x in ["RegSetValue", "SetWindowsHook"]):
            predictions.append("Likely attempts to establish persistence on the host system.")
        
        # Network markers
        if self.static.get("strings", {}).get("Network") or (self.dynamic.get("data", {}).get("network_info", {}).get("hosts")):
            predictions.append("May communicate with a Command & Control (C2) server or download external payloads.")

        # Dynamic markers
        if self.dynamic.get("status") == "SUCCESS":
            mitre = self.dynamic.get("data", {}).get("mitre_attcks", [])
            for attack in mitre[:3]:
                predictions.append(f"Exhibits technique: {attack.get('tactic')} ({attack.get('technique')})")

        if not predictions:
            predictions.append("No highly suspicious behavioral patterns identified.")
            
        self.predictions = predictions
        return predictions

    def get_risk_level(self) -> str:
        """Determine risk level (LOW/MEDIUM/HIGH)."""
        for level, (low, high) in RISK_LEVELS.items():
            if low <= self.score <= high:
                return level
        return "UNKNOWN"

    def generate_full_report(self) -> Dict[str, Any]:
        """Assemble the complete analysis report."""
        self.calculate_score()
        self.generate_predictions()
        
        return {
            "summary": {
                "risk_score": self.score,
                "risk_level": self.get_risk_level(),
                "predictions": self.predictions,
                "triggered_rules": self.triggered_rules
            },
            "static_analysis": self.static,
            "dynamic_analysis": self.dynamic
        }
