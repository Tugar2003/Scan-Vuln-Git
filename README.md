# Scan-Vuln-Git
Automatically clone and scan public GitHub repositories for real, reproducible vulnerabilities. Generates detailed reports for bug bounty and security research.

## ✨ Features

- 🔍 Clones and scans any public GitHub repository
- 💥 Detects reproducible vulnerabilities like:
  - XSS
  - ReDoS
  - DoS
  - Directory Traversal
  - And more...
- 🚫 Skips unnecessary files (e.g., test, sample folders)
- 📑 Generates:
  - `bug_report.md` — human-readable report
  - `bug_report.json` — structured JSON report
- 🖼️ Displays custom startup logo

---

## 📦 Installation

```bash
git clone https://github.com/your-username/scan-vuln-git.git
cd scan-vuln-git
pip install -r requirements.txt
```

## 👩‍💻Usage
python main.py <github_repo_url>

