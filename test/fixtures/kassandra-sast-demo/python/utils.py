"""
Utility module with Command Injection vulnerabilities.
CWE-78: OS Command Injection
Severity: CRITICAL
"""

import os
import subprocess
from typing import Optional


# VULNERABILITY: Command Injection via os.system
def ping_host(host: str) -> int:
    """
    Ping a host - VULNERABLE to Command Injection.

    Example attack: host = "google.com; rm -rf /"
    """
    # BAD: Direct string concatenation with os.system
    command = "ping -c 1 " + host
    return os.system(command)


# VULNERABILITY: Command Injection via subprocess with shell=True
def get_file_info(filename: str) -> str:
    """
    Get file info - VULNERABLE to Command Injection.

    Example attack: filename = "test.txt; cat /etc/passwd"
    """
    # BAD: shell=True with unsanitized input
    result = subprocess.run(
        f"ls -la {filename}",
        shell=True,
        capture_output=True,
        text=True
    )
    return result.stdout


# VULNERABILITY: Command Injection via os.popen
def count_lines(filepath: str) -> int:
    """
    Count lines in file - VULNERABLE to Command Injection.

    Example attack: filepath = "test.txt; whoami"
    """
    # BAD: os.popen with unsanitized input
    result = os.popen(f"wc -l {filepath}").read()
    try:
        return int(result.split()[0])
    except (ValueError, IndexError):
        return 0


# VULNERABILITY: Command Injection via subprocess.Popen
def compress_file(filename: str, output: str) -> bool:
    """
    Compress a file - VULNERABLE to Command Injection.

    Example attack: filename = "test.txt; id > /tmp/pwned"
    """
    # BAD: Popen with shell=True
    process = subprocess.Popen(
        f"gzip -c {filename} > {output}",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    process.wait()
    return process.returncode == 0


# VULNERABILITY: eval() with user input
def calculate(expression: str) -> Optional[float]:
    """
    Calculate expression - VULNERABLE to Code Injection.

    Example attack: expression = "__import__('os').system('whoami')"
    """
    # BAD: eval with user input
    try:
        return eval(expression)
    except Exception:
        return None


# VULNERABILITY: exec() with user input
def run_code(code: str) -> str:
    """
    Run Python code - VULNERABLE to Code Injection.

    Example attack: code = "import os; os.system('id')"
    """
    # BAD: exec with user input
    output = {}
    try:
        exec(code, {"__builtins__": {}}, output)
        return str(output)
    except Exception as e:
        return str(e)


# SECURE EXAMPLE: Using subprocess without shell
def ping_host_secure(host: str) -> int:
    """
    Ping a host - SECURE version without shell.
    """
    import shlex

    # GOOD: List of arguments, no shell
    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True
    )
    return result.returncode
