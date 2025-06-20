import os
import json

# Limit block sizes to prevent huge reports
MAX_LINES = 20

def limit_lines(text):
    lines = text.strip().splitlines()
    if len(lines) > MAX_LINES:
        return "\n".join(lines[:MAX_LINES]) + "\n... [truncated]"
    return text

def generate_report(vulns, output_path):
    if not vulns:
        print("No vulnerabilities found.")
        return

    try:
        with open(output_path, "w", encoding='utf-8') as f:
            f.write("# Bug Report\n\n")
            f.write(f"Repo scanned: {os.path.basename(os.path.dirname(output_path))}\n\n")
            f.write(f"Total vulnerabilities found: {len(vulns)}\n\n")

            for i, v in enumerate(vulns, 1):
                f.write(f"## Vulnerability {i}: {v['type']}\n")
                f.write(f"- **File:** {v['file']}\n")
                f.write(f"- **Line:** {v['line']}\n")
                f.write(f"- **Description:** {v['description']}\n")
                f.write(f"- **CVSS Score:** {v.get('cvss', 'N/A')}\n")
                f.write(f"- **Reference:** {v.get('reference', 'N/A')}\n")
                f.write(f"- **Proof of Concept:**\n```\n{limit_lines(v.get('poc', ''))}\n```\n")
                f.write(f"- **Code Snippet:**\n```\n{limit_lines(v.get('snippet', ''))}\n```\n\n")

        print(f"[+] Bug report generated at: {output_path}")
    except Exception as e:
        print(f"[-] Failed to write markdown report: {e}")

def generate_json_report(vulns, output_path):
    try:
        with open(output_path, "w", encoding='utf-8') as f:
            json.dump(vulns, f, indent=2)
        print(f"[+] JSON report generated at: {output_path}")
    except Exception as e:
        print(f"[-] Failed to write JSON report: {e}")

