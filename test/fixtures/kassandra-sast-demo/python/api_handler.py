"""
API Handler with Multiple Vulnerabilities.
Added for SAST workflow validation.
"""

import subprocess
import requests
import sqlite3
import xml.etree.ElementTree as ET


# VULNERABILITY: Server-Side Request Forgery (SSRF)
# CWE-918: Server-Side Request Forgery
def fetch_url(user_provided_url):
    """Fetch content from user-provided URL - VULNERABLE to SSRF."""
    response = requests.get(user_provided_url)  # BAD: No URL validation
    return response.text


# VULNERABILITY: XML External Entity (XXE)
# CWE-611: Improper Restriction of XML External Entity Reference
def parse_xml(xml_string):
    """Parse XML without disabling external entities - VULNERABLE."""
    tree = ET.fromstring(xml_string)  # BAD: XXE possible
    return tree


# VULNERABILITY: Command Injection via shell=True
# CWE-78: OS Command Injection
def run_system_command(user_input):
    """Execute system command with user input - VULNERABLE."""
    result = subprocess.run(
        f"echo {user_input}",
        shell=True,  # BAD: shell=True with user input
        capture_output=True
    )
    return result.stdout


# VULNERABILITY: SQL Injection with string formatting
# CWE-89: SQL Injection
def get_user_by_email(email):
    """Get user by email using string formatting - VULNERABLE."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE email = '{email}'"  # BAD: SQL injection
    cursor.execute(query)
    return cursor.fetchone()


# VULNERABILITY: Hardcoded credentials
# CWE-798: Use of Hard-coded Credentials
ADMIN_PASSWORD = "admin123"
API_SECRET = "sk-secret-key-12345"
DATABASE_PASSWORD = "SuperSecret123!"


# VULNERABILITY: Insecure random for security purposes
# CWE-330: Use of Insufficiently Random Values
import random

def generate_token():
    """Generate token using insecure random - VULNERABLE."""
    return ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=32))


# VULNERABILITY: Path traversal
# CWE-22: Path Traversal
def read_file(filename):
    """Read file without path validation - VULNERABLE."""
    with open(f"/var/data/{filename}", "r") as f:  # BAD: Path traversal
        return f.read()


# VULNERABILITY: Insecure deserialization
# CWE-502: Deserialization of Untrusted Data
import pickle

def load_user_data(serialized_data):
    """Load pickled data from user - VULNERABLE."""
    return pickle.loads(serialized_data)  # BAD: Arbitrary code execution
