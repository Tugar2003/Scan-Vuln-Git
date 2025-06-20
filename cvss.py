# Simplified CVSS score calculator based on vulnerability type & severity

CVSS_BASE_SCORES = {
    "XSS": 6.1,
    "ReDoS": 7.5,
    "DoS": 5.0,
    "Directory Traversal": 7.5,
}

def estimate_cvss(vuln_type: str):
    return CVSS_BASE_SCORES.get(vuln_type, 5.0)

