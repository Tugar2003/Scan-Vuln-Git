import re

def scan(code: str, lang: str, filepath: str):
    vulns = []
    # Directory traversal patterns: look for file paths or user input used directly in file access

    # Basic regex for suspicious file access in code (python open, js fs.readFile, etc)
    patterns = [
        r'open\((.+)\)',               # python
        r'fs\.readFileSync\((.+)\)',  # js
        r'FileStream\((.+)\)',        # C#, Java, C++
    ]

    for pattern in patterns:
        import re
        matches = re.findall(pattern, code)
        for match in matches:
            if '../' in match or '..\\' in match or '%2e%2e' in match.lower():
                line = find_line(code, match)
                snippet = extract_snippet(code, match)
                vulns.append({
                    "type": "Directory Traversal",
                    "file": filepath,
                    "line": line,
                    "snippet": snippet,
                    "description": "Potential directory traversal via unsanitized file path input",
                    "poc": "Craft input like ../../etc/passwd to access unauthorized files",
                    "cvss": 7.5,
                    "reference": "https://owasp.org/www-community/attacks/Path_Traversal",
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

