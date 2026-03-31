import os

# Hybrid Analysis API Configuration
# Get your API key from https://www.hybrid-analysis.com/api-details
API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY", "xy6p2jzb1aa36ec4qvvqllw699f875abzxb2ds1oe0a7cd22u8j0h3az1e981d03")
BASE_URL = "https://www.hybrid-analysis.com/api/v2"

# Scanning Constants
POLL_INTERVAL = 10  # Seconds
MAX_POLL_ATTEMPTS = 30  # 5 minutes total
TIMEOUT = 60  # Request timeout

# Risk Scoring Weights
WEIGHTS = {
    "high_entropy": 15,
    "packed": 20,
    "suspicious_import": 10,
    "network_string": 5,
    "persistence_string": 10,
    "malicious_keyword": 8,
    "dynamic_malicious_verdict": 50,
    "dynamic_suspicious_verdict": 25,
    "dynamic_network_activity": 15,
}

# Risk Tiers
RISK_LEVELS = {
    "LOW": (0, 20),
    "MEDIUM": (21, 50),
    "HIGH": (51, 1000)
}
