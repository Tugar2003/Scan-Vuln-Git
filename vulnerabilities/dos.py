def scan(code: str, lang: str, filepath: str):
    vulns = []
    # Detect common DoS patterns such as unbounded loops, or fork bombs in code.

    # Simplified example: infinite while loops without breaks in python or js
    patterns = {
        "python": [r'while True:', r'while 1:'],
        "javascript": [r'while\s*\(true\)'],
        # You can add other patterns for C, C++, etc.
    }

    if lang in patterns:
        for pattern in patterns[lang]:
            import re
            matches = re.findall(pattern, code, re.IGNORECASE)
            for match in matches:
                line = find_line(code, pattern)
                snippet = extract_snippet(code, pattern)
                vulns.append({
                    "type": "DoS",
                    "file": filepath,
                    "line": line,
                    "snippet": snippet,
                    "description": "Potential infinite loop causing Denial of Service",
                    "poc": "Run code to observe infinite loop blocking execution",
                    "cvss": 5.0,
                    "reference": "https://owasp.org/www-community/attacks/Denial_of_Service",
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

