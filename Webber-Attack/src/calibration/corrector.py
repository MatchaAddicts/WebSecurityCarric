import json
import os
from typing import Tuple, Dict, Any

class OWASPCorrector:
    """
    OWASP Top 10:2025 Calibration Engine.
    
    Enforces strict categorization rules:
    1. JWT/Token/Cookie manipulation -> A01 (Broken Access Control)
    2. Juice Shop Challenge Names -> Mapped to correct 2025 Category
    3. Technical Signatures -> Universal Fallback
    """
    
    def __init__(self, baseline_file: str = "data/owasp_2025_baseline.json"):
        self.signatures = []
        self.juice_map = {}
        self.loaded = False
        
        # Calculate absolute path to data file
        # Logic: current_file -> src/calibration -> src -> root -> data/
        base_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.file_path = os.path.join(base_path, baseline_file)
        
        self._load_baseline()

    def _load_baseline(self):
        """Load the JSON baseline file safely."""
        if not os.path.exists(self.file_path):
            print(f"[Corrector] ⚠️ Baseline not found at {self.file_path}. Run 'python3 tools/generate_baseline.py'.")
            return

        try:
            with open(self.file_path, 'r') as f:
                data = json.load(f)
                self.signatures = data.get("signatures", [])
                self.juice_map = data.get("juice_shop_challenges", {})
                self.loaded = True
        except Exception as e:
            print(f"[Corrector] ❌ Error loading baseline JSON: {e}")

    def correct(self, agent_report: Dict[str, Any]) -> Tuple[bool, Dict[str, Any], str]:
        modified = False
        reason = ""
        data = agent_report.copy()
        
        # Normalize inputs
        current_cat = str(data.get("owasp_category", "")).upper()
        title = str(data.get("vuln_type", "")).strip()
        payload = str(data.get("payload", "")).lower()
        evidence = str(data.get("evidence", "")).lower()
        
        combined_signals = f"{payload} {evidence} {title}".lower()

        # RULE 0: HARD ENFORCEMENT (JWT = A01)
        if any(x in combined_signals for x in ["jwt", "token", "session", "cookie"]):
            # Exclude XSS/SQLi that might just happen to be in a cookie
            if not any(x in combined_signals for x in ["<script", "alert(", "union select"]):
                if current_cat != "A01":
                    data["owasp_category"] = "A01"
                    if "A0" in title or "Unknown" in title:
                        data["vuln_type"] = "Session/Auth Manipulation"
                    return True, data, "Strict Enforcement: Session/Token issues are A01 Access Control"

        # RULE 1: JUICE SHOP BASELINE
        for challenge_name, correct_cat in self.juice_map.items():
            if challenge_name.lower() in title.lower():
                if current_cat != correct_cat:
                    data["owasp_category"] = correct_cat
                    modified = True
                    reason = f"Baseline Match: '{challenge_name}' maps to {correct_cat}"
                    return modified, data, reason

        # RULE 2: TECHNICAL SIGNATURES
        if self.loaded:
            for sig in self.signatures:
                match = False
                sig_cat = sig["category"]
                
                for indicator in sig["indicators"]:
                    indicator = indicator.lower()
                    if sig.get("must_match_payload", False):
                        if indicator in payload: match = True
                    else:
                        if indicator in combined_signals: match = True
                    if match: break
                
                if match:
                    if current_cat != sig_cat:
                        data["owasp_category"] = sig_cat
                        modified = True
                        reason = f"Signature Match: Found '{indicator}' -> {sig_cat}"
                        return modified, data, reason

        return modified, data, reason