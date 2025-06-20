# utils.py

EXTENSION_MAP = {
    '.py': 'python',
    '.js': 'javascript',
    '.c': 'c',
    '.cpp': 'cpp',
    '.cc': 'cpp',
    '.h': 'c',
    '.hpp': 'cpp',
    '.cs': 'csharp',
    '.java': 'java',
    '.ts': 'typescript',
    '.rb': 'ruby',
    '.go': 'go',
    '.php': 'php',
    '.html': 'html',
}

def get_language_from_extension(ext):
    return EXTENSION_MAP.get(ext.lower(), None)

