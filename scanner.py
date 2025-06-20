import os
from vulnerabilities import xss, redos, dos, dir_traversal
from utils import get_language_from_extension

# Vulnerability modules to scan for
VULNERABILITY_MODULES = [xss, redos, dos, dir_traversal]

# Directories and file extensions to skip
SKIP_FOLDERS = ['test', 'tests', '__tests__', 'samples', 'examples', 'docs', 'node_modules', 'venv', '.git']
SKIP_EXTENSIONS = ['.spec.', '.test.']
SKIP_FILETYPES = ['.jpg', '.jpeg', '.png', '.gif', '.exe', '.pdf', '.zip', '.tar', '.gz']

# Max file size (in bytes) to scan (e.g., 300 KB)
MAX_FILE_SIZE = 300 * 1024

def is_skipped(filepath):
    lowered = filepath.lower()

    # Skip by directory name
    if any(skip in lowered for skip in SKIP_FOLDERS):
        return True

    # Skip by filename extension pattern (e.g., file.spec.js)
    if any(ext in lowered for ext in SKIP_EXTENSIONS):
        return True

    # Skip binary or non-code files
    ext = os.path.splitext(filepath)[1].lower()
    if ext in SKIP_FILETYPES:
        return True

    # Skip large files
    if os.path.exists(filepath) and os.path.getsize(filepath) > MAX_FILE_SIZE:
        return True

    return False

def scan_file(filepath):
    if is_skipped(filepath):
        return []

    ext = os.path.splitext(filepath)[1]
    lang = get_language_from_extension(ext)
    if not lang:
        return []

    try:
        with open(filepath, errors='ignore') as f:
            code = f.read()
    except Exception as e:
        print(f"[-] Failed to read {filepath}: {e}")
        return []

    vulns = []
    for module in VULNERABILITY_MODULES:
        results = module.scan(code, lang, filepath)
        if results:
            vulns.extend(results)
    return vulns

def scan_repo(repo_path):
    all_vulns = []
    seen = set()

    for root, dirs, files in os.walk(repo_path):
        # Skip entire unwanted directories
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_FOLDERS]

        for file in files:
            filepath = os.path.join(root, file)
            if is_skipped(filepath):
                continue

            vulns = scan_file(filepath)
            for v in vulns:
                key = (v["file"], v["line"], v["type"], v["snippet"])
                if key not in seen:
                    seen.add(key)
                    all_vulns.append(v)

    return all_vulns

