import re

def scan(code: str, lang: str, filepath: str):
    vulns = []
    # ReDoS is often in regex patterns vulnerable to catastrophic backtracking
    # We’ll look for common vulnerable regex patterns in all code

    # List of risky regex patterns known for ReDoS (simplified examples)
    risky_patterns = [
        r'(a+)+',
        r'(.*)+',
        r'(a|aa)+',
        r'([a-zA-Z]+)+',
        r'(\d+)+',
    ]

    for pattern in risky_patterns:
        matches = re.findall(pattern, code)
        if matches:
            for m in matches:
                line = find_line(code, pattern)
                snippet = extract_snippet(code, pattern)
                vulns.append({
                    "type": "ReDoS",
                    "file": filepath,
                    "line": line,
                    "snippet": snippet,
                    "description": f"Potential ReDoS vulnerable regex pattern: {pattern}",
                    "poc": f"Input crafted to exploit regex: 'aaaaaa...'",
                    "cvss": 7.5,
                    "reference": "https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS",
                })
    return vulns

def find_line(code, snippet):
    lines = code.splitlines()
    for i, line in enumerate(lines, 1):
        if snippet in line:
            return i
    return -1

def extract_snippet(code, snippet, context=2):
    lines = code.splitlines()
    for i, line in enumerate(lines):
        if snippet in line:
            start = max(i - context, 0)
            end = min(i + context + 1, len(lines))
            return "\n".join(lines[start:end])
    return snippet

