import yaml
import json
import os

# =============================================================================
# 1. TECHNICAL SIGNATURES (The "Universal" Rules)
# =============================================================================
# These allow the Corrector to fix findings on ANY website (Juice Shop or Custom).
# NOTICE: JWT signatures are strictly placed under A01.
SIGNATURES = [
    {
        "category": "A01",
        "type": "Broken Access",
        "indicators": ["Access Denied", "Unauthorized", "403 Forbidden", "admin panel", "role: admin"],
        "must_match_payload": False
    },
    {
        "category": "A01", 
        "type": "JWT Manipulation",
        "indicators": ["eyJ", "Bearer ", "jwt_decode", "unsigned token", "none algorithm"],
        "must_match_payload": False
    },
    {
        "category": "A05",
        "type": "Injection",
        "indicators": ["' OR 1=1", "SQL syntax", "mysql_error", "UNION SELECT", "<script>", "alert(1)", "onerror="],
        "must_match_payload": True
    },
    {
        "category": "A06",
        "type": "Insecure Design",
        "indicators": ["coupon", "discount", "negative balance", "logic error", "business logic"],
        "must_match_payload": False
    },
    {
        "category": "A10",
        "type": "Unhandled Exception",
        "indicators": ["Traceback", "NullPointerException", "SyntaxError", "Fatal error", "internal server error"],
        "must_match_payload": False
    },
    {
        "category": "A03",
        "type": "Supply Chain",
        "indicators": ["package.json", "node_modules", "composer.json", "yarn.lock", "jquery-", "outdated"],
        "must_match_payload": False
    },
    {
        "category": "A04",
        "type": "Weak Crypto",
        "indicators": ["Basic YWRtaW46", "md5(", "sha1(", "-----BEGIN RSA PRIVATE KEY-----"],
        "must_match_payload": False
    },
    {
        "category": "A08",
        "type": "Integrity Failure",
        "indicators": ["rO0AB", "cafebabe", "AC ED 00 05", "serialization", "object input stream"],
        "must_match_payload": False
    },
    {
        "category": "A02",
        "type": "Misconfiguration",
        "indicators": [".env", "phpinfo()", "server-status", "Index of /"],
        "must_match_payload": False
    },
    {
        "category": "A09",
        "type": "Logging Failure",
        "indicators": ["access.log", "error.log", "splunk", "no logging detected"],
        "must_match_payload": False
    },
    {
        "category": "A07",
        "type": "Auth Failure",
        "indicators": ["Invalid password", "User not found", "session_id", "PHPSESSID"],
        "must_match_payload": False
    }
]

# =============================================================================
# 2. CHALLENGE OVERRIDES (Specific Fixes)
# =============================================================================
# Force specific challenges to the correct 2025 category regardless of their old label.
OVERRIDES = {
    # JWT Challenges -> A01 (Strict Compliance)
    "Forged Signed JWT": "A01",
    "Unsigned JWT": "A01",
    "Retrieve Blueprint": "A04", # Product file -> Crypto/Data Exposure
    
    # Logic/Design Flaws -> A06 (Insecure Design)
    "Repetitive Registration": "A06",
    "Zero Stars": "A06",
    "Forged Coupon": "A06",
    "CAPTCHA Bypass": "A06",
    
    # Error Handling -> A10 (Exceptions)
    "Error Handling": "A10",
    "Outdated Allowlist": "A10",
    
    # Deserialization -> A08 (Integrity)
    "Successful RCE DoS": "A08", 
    "Memory Bomb": "A08" 
}

# =============================================================================
# 3. LEGACY CATEGORY MAPPING (Broad Rules)
# =============================================================================
CATEGORY_MAP = {
    "Injection": "A05:2025 Injection",
    "XSS": "A05:2025 Injection", 
    "Broken Access Control": "A01:2025 Broken Access Control",
    "IDOR": "A01:2025 Broken Access Control", 
    "Sensitive Data Exposure": "A04:2025 Cryptographic Failures",
    "Cryptographic Issues": "A04:2025 Cryptographic Failures",
    "Broken Authentication": "A07:2025 Authentication Failures",
    "Security Misconfiguration": "A02:2025 Security Misconfiguration",
    "Insecure Design": "A06:2025 Insecure Design",
    "Broken Anti Automation": "A06:2025 Insecure Design",
    "Vulnerable Components": "A03:2025 Software Supply Chain Failures",
    "Observability Failures": "A09:2025 Security Logging Failures",
    "Improper Input Validation": "A10:2025 Mishandling of Exceptional Conditions"
}

def generate():
    input_file = 'challenges.yml'
    output_file = 'data/owasp_2025_baseline.json'

    # Ensure input exists
    if not os.path.exists(input_file):
        print(f"❌ Error: '{input_file}' not found in current directory.")
        return

    print(f"📂 Reading {input_file}...")
    try:
        with open(input_file, 'r') as f:
            raw_challenges = yaml.safe_load(f)
    except Exception as e:
        print(f"❌ Error parsing YAML: {e}")
        return

    baseline = {
        "meta": {
            "version": "2025.3", 
            "description": "OWASP Top 10:2025 - Strict User Compliance (JWT=A01)"
        },
        "signatures": SIGNATURES,
        "juice_shop_challenges": {}
    }

    print("🔄 Processing challenges...")
    
    for task in raw_challenges:
        name = task.get('name')
        old_cat = task.get('category', 'Miscellaneous')
        
        # 1. Check for Specific Override first
        if name in OVERRIDES:
            short_cat = OVERRIDES[name]
        else:
            # 2. Fallback to Category Mapping
            full_new_cat = CATEGORY_MAP.get(old_cat, "A06:2025 Insecure Design")
            short_cat = full_new_cat.split(":")[0]

        # 3. Store
        baseline["juice_shop_challenges"][name] = short_cat

    # Create directory if missing
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    # Write JSON
    with open(output_file, 'w') as f:
        json.dump(baseline, f, indent=2)
    
    print(f"✅ SUCCESS: Mapped {len(raw_challenges)} challenges.")
    print(f"📄 Generated: {output_file}")

if __name__ == "__main__":
    generate()