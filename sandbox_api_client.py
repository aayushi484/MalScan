import requests
import time
import hashlib
import os
from typing import Dict, Any, Optional
from config import API_KEY, BASE_URL, POLL_INTERVAL, MAX_POLL_ATTEMPTS, TIMEOUT

class SandboxClient:
    """
    Client for Hybrid Analysis (InQuest) dynamic analysis.
    Supports file search by hash and submission for behavioral reporting.
    """

    def __init__(self):
        self.headers = {
            "api-key": API_KEY,
            "user-agent": "Falcon Sandbox"
        }

    def check_hash(self, sha256: str) -> Optional[Dict[str, Any]]:
        """Check if a report already exists for the given hash."""
        url = f"{BASE_URL}/search/hash"
        data = {"hash": sha256}
        try:
            response = requests.post(url, data=data, headers=self.headers, timeout=TIMEOUT)
            if response.status_code == 200:
                results = response.json()
                if results:
                    # Return the first (most recent) report summary
                    return results[0]
        except Exception as e:
            print(f"Error checking hash: {e}")
        return None

    def submit_file(self, file_path: str, file_name: str) -> Optional[str]:
        """Submit a file for dynamic analysis and return the job ID."""
        url = f"{BASE_URL}/submit/file"
        try:
            with open(file_path, "rb") as f:
                files = {"file": (file_name, f)}
                data = {"environment_id": 160}  # 160 = Windows 10 64-bit
                response = requests.post(url, files=files, data=data, headers=self.headers, timeout=TIMEOUT)
                if response.status_code == 201:
                    return response.json().get("job_id")
        except Exception as e:
            print(f"Error submitting file: {e}")
        return None

    def get_summary(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get the summary of a completed job."""
        url = f"{BASE_URL}/report/{job_id}/summary"
        try:
            response = requests.get(url, headers=self.headers, timeout=TIMEOUT)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"Error getting summary: {e}")
        return None

    def poll_until_finished(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Poll the job status until it is finished or timeout reached."""
        for _ in range(MAX_POLL_ATTEMPTS):
            summary = self.get_summary(job_id)
            if summary and summary.get("analysis_start_time"):
                # Check for state - if threat_score is present, it's likely done
                if "threat_score" in summary:
                    return summary
            time.sleep(POLL_INTERVAL)
        return None

    def get_full_report(self, file_path: str) -> Dict[str, Any]:
        """Orchestrate the dynamic analysis flow."""
        sha256 = hashlib.sha256(open(file_path, "rb").read()).hexdigest()
        file_name = os.path.basename(file_path)

        # 1. Check if report exists
        existing_report = self.check_hash(sha256)
        if existing_report:
            return {"status": "SUCCESS", "source": "Cache", "data": existing_report}

        # 2. Submit file
        job_id = self.submit_file(file_path, file_name)
        if not job_id:
            return {"status": "FAILED", "error": "Submission failed"}

        # 3. Poll for results
        final_report = self.poll_until_finished(job_id)
        if final_report:
            return {"status": "SUCCESS", "source": "New Analysis", "data": final_report}

        return {"status": "FAILED", "error": "Analysis timed out or failed"}
