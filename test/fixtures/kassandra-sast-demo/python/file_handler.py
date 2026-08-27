"""
File handling module with Path Traversal vulnerabilities.
CWE-22: Path Traversal
Severity: HIGH
"""

import os
from pathlib import Path
from typing import Optional


UPLOAD_DIR = "/var/www/uploads"
STATIC_DIR = "/var/www/static"


# VULNERABILITY: Path Traversal in file read
def read_user_file(filename: str) -> str:
    """
    Read user file - VULNERABLE to Path Traversal.

    Example attack: filename = "../../../etc/passwd"
    """
    # BAD: Direct concatenation without validation
    filepath = os.path.join(UPLOAD_DIR, filename)
    with open(filepath, 'r') as f:
        return f.read()


# VULNERABILITY: Path Traversal in file write
def save_user_file(filename: str, content: str) -> str:
    """
    Save user file - VULNERABLE to Path Traversal.

    Example attack: filename = "../../app/config.py"
    """
    # BAD: No path validation
    filepath = os.path.join(UPLOAD_DIR, filename)
    with open(filepath, 'w') as f:
        f.write(content)
    return filepath


# VULNERABILITY: Path Traversal in file delete
def delete_user_file(filename: str) -> bool:
    """
    Delete user file - VULNERABLE to Path Traversal.

    Example attack: filename = "../../../var/log/important.log"
    """
    # BAD: No validation before delete
    filepath = os.path.join(UPLOAD_DIR, filename)
    if os.path.exists(filepath):
        os.remove(filepath)
        return True
    return False


# VULNERABILITY: Path Traversal with Path
def get_static_file(filename: str) -> Optional[bytes]:
    """
    Get static file - VULNERABLE to Path Traversal.
    """
    # BAD: Using Path doesn't prevent traversal
    filepath = Path(STATIC_DIR) / filename
    if filepath.exists():
        return filepath.read_bytes()
    return None


# VULNERABILITY: Symlink attack
def read_with_symlink(filename: str) -> str:
    """
    Read file following symlinks - VULNERABLE.

    Attacker could create symlink pointing to sensitive file.
    """
    # BAD: Follows symlinks without checking
    filepath = os.path.join(UPLOAD_DIR, filename)
    return open(filepath).read()


# VULNERABILITY: Archive extraction (Zip Slip)
def extract_archive(archive_path: str, extract_to: str) -> list:
    """
    Extract archive - VULNERABLE to Zip Slip.

    Malicious archives can contain paths like ../../evil.sh
    """
    import zipfile

    extracted = []
    with zipfile.ZipFile(archive_path, 'r') as zip_ref:
        for member in zip_ref.namelist():
            # BAD: No path validation before extraction
            zip_ref.extract(member, extract_to)
            extracted.append(member)
    return extracted


# SECURE EXAMPLE: Path validation
def read_user_file_secure(filename: str) -> Optional[str]:
    """
    Read user file securely - SECURE.
    """
    # GOOD: Validate path stays within allowed directory
    base = Path(UPLOAD_DIR).resolve()
    filepath = (base / filename).resolve()

    # Ensure path is within upload directory
    if not str(filepath).startswith(str(base)):
        raise ValueError("Path traversal detected")

    if filepath.exists() and filepath.is_file():
        return filepath.read_text()
    return None


# SECURE EXAMPLE: Safe archive extraction
def extract_archive_secure(archive_path: str, extract_to: str) -> list:
    """
    Extract archive safely - SECURE.
    """
    import zipfile

    extracted = []
    base = Path(extract_to).resolve()

    with zipfile.ZipFile(archive_path, 'r') as zip_ref:
        for member in zip_ref.namelist():
            # GOOD: Validate each path before extraction
            target = (base / member).resolve()
            if not str(target).startswith(str(base)):
                raise ValueError(f"Zip slip detected: {member}")
            zip_ref.extract(member, extract_to)
            extracted.append(member)
    return extracted
