import os
import shutil
import subprocess

def clone_repo(github_url: str, clone_dir="repos") -> str:
    if not os.path.exists(clone_dir):
        os.makedirs(clone_dir)
    repo_name = github_url.rstrip('/').split('/')[-1]
    repo_path = os.path.join(clone_dir, repo_name)

    # Delete if exists to refresh clone
    if os.path.exists(repo_path):
        shutil.rmtree(repo_path)

    cmd = ["git", "clone", github_url, repo_path]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return repo_path
    except subprocess.CalledProcessError as e:
        print(f"Error cloning repo: {e}")
        return ""

