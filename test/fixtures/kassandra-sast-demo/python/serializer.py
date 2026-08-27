"""
Serialization module with Insecure Deserialization.
CWE-502: Deserialization of Untrusted Data
Severity: HIGH
"""

import pickle
import yaml
import json
from typing import Any


# VULNERABILITY: Pickle deserialization of untrusted data
def load_user_data(data: bytes) -> Any:
    """
    Load user data from pickle - VULNERABLE.

    Pickle can execute arbitrary code during deserialization.
    Example payload: Create malicious pickle that runs os.system()
    """
    # BAD: pickle.loads with untrusted data
    return pickle.loads(data)


# VULNERABILITY: Pickle from file
def load_from_file(filepath: str) -> Any:
    """
    Load object from pickle file - VULNERABLE.
    """
    # BAD: pickle.load with untrusted file
    with open(filepath, 'rb') as f:
        return pickle.load(f)


# VULNERABILITY: Unsafe YAML load
def parse_yaml_config(yaml_string: str) -> dict:
    """
    Parse YAML configuration - VULNERABLE.

    yaml.load can execute Python code via !!python/object tag.
    Example payload: !!python/object/apply:os.system ["id"]
    """
    # BAD: yaml.load without safe_load
    return yaml.load(yaml_string, Loader=yaml.Loader)


# VULNERABILITY: Unsafe YAML load (legacy)
def parse_yaml_legacy(yaml_string: str) -> dict:
    """
    Parse YAML with legacy loader - VULNERABLE.
    """
    # BAD: yaml.load without specifying safe loader
    return yaml.load(yaml_string)


# VULNERABILITY: Marshal deserialization
def load_marshal_data(data: bytes) -> Any:
    """
    Load data using marshal - VULNERABLE.

    Marshal is not secure for untrusted data.
    """
    import marshal

    # BAD: marshal.loads with untrusted data
    return marshal.loads(data)


# VULNERABILITY: Shelve with untrusted data
def load_shelve_data(filepath: str, key: str) -> Any:
    """
    Load data from shelve file - VULNERABLE.

    Shelve uses pickle internally.
    """
    import shelve

    # BAD: shelve uses pickle
    with shelve.open(filepath) as db:
        return db.get(key)


# VULNERABILITY: dill deserialization
def load_dill_data(data: bytes) -> Any:
    """
    Load data using dill - VULNERABLE.

    dill extends pickle and has same vulnerabilities.
    """
    import dill

    # BAD: dill.loads with untrusted data
    return dill.loads(data)


# SECURE EXAMPLE: Using JSON
def parse_json_secure(json_string: str) -> dict:
    """
    Parse JSON configuration - SECURE.

    JSON cannot execute code during parsing.
    """
    # GOOD: JSON is safe for deserialization
    return json.loads(json_string)


# SECURE EXAMPLE: Using safe YAML
def parse_yaml_secure(yaml_string: str) -> dict:
    """
    Parse YAML safely - SECURE.
    """
    # GOOD: safe_load prevents code execution
    return yaml.safe_load(yaml_string)
