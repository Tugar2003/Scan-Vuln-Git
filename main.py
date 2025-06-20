import argparse
import os
from crawler import clone_repo
from scanner import scan_repo
from reporter import generate_report
from reporter import generate_json_report  # You’ll implement this next

def print_logo():
    try:
        from pyfiglet import Figlet
        f = Figlet(font='slant')
        print(f.renderText('Scan-Vuln-Git'))
    except ImportError:
        print("Scan-Vuln-Git")
        print("[!] Install pyfiglet for a better logo: pip install pyfiglet")

def main(repo_url, show_logo=True, output_path=None, generate_json=False):
    if show_logo:
        print_logo()

    print(f"[+] Cloning repo: {repo_url}")
    repo_path = clone_repo(repo_url)
    if not repo_path:
        print("[-] Failed to clone repo.")
        return

    print("[+] Scanning repo for vulnerabilities...")
    vulns = scan_repo(repo_path)

    print("[+] Generating bug report...")
    if output_path is None:
        output_path = os.path.join(repo_path, "bug_report.md")
    generate_report(vulns, output_path)

    if generate_json:
        json_path = output_path.replace(".md", ".json")
        generate_json_report(vulns, json_path)

    print(f"[+] Done. Report saved to: {output_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Scan-Vuln-Git: Automatically scan a public GitHub repo for vulnerabilities and generate a detailed report."
    )
    parser.add_argument("repo_url", type=str, help="Public GitHub repository URL to scan")
    parser.add_argument("--no-logo", action="store_true", help="Suppress ASCII logo on start")
    parser.add_argument("--output", type=str, help="Custom output path for Markdown report")
    parser.add_argument("--json", action="store_true", help="Also generate a JSON report")

    args = parser.parse_args()

    main(
        repo_url=args.repo_url,
        show_logo=not args.no_logo,
        output_path=args.output,
        generate_json=args.json
    )

