import re

def scan(code: str, lang: str, filepath: str):
    vulns = []
    if lang not in ("javascript", "python"):
        return []

    # Very simple example pattern: look for document.write or eval or unsanitized output in JS
    if lang == "javascript":
        # Basic example: look for document.write with non-literal input
        pattern = re.compile(r'document\.write\((.+)\)', re.I)
        matches = pattern.findall(code)
        for match in matches:
            # In a real scanner, analyze if input is sanitized, here we just flag all
            vulns.append({
                "type": "XSS",
                "file": filepath,
                "line": find_line(code, match),
                "snippet": extract_snippet(code, match),
                "description": "Potential XSS via document.write with dynamic input",
                "poc": f"Inject JS code via {match}",
                "cvss": 6.1,  # example CVSS
                "reference": "https://owasp.org/www-community/attacks/xss/",
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

