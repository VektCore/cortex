"""
Authentication module with Weak Cryptography.
CWE-328: Use of Weak Hash
CWE-327: Use of Broken Crypto Algorithm
Severity: MEDIUM
"""

import hashlib
import base64
from typing import Optional


# VULNERABILITY: Using MD5 for password hashing
def hash_password_md5(password: str) -> str:
    """
    Hash password with MD5 - VULNERABLE (weak hash).

    MD5 is cryptographically broken and unsuitable for security.
    """
    # BAD: MD5 is weak
    return hashlib.md5(password.encode()).hexdigest()


# VULNERABILITY: Using SHA1 for password hashing
def hash_password_sha1(password: str) -> str:
    """
    Hash password with SHA1 - VULNERABLE (weak hash).

    SHA1 has known collision attacks.
    """
    # BAD: SHA1 is weak
    return hashlib.sha1(password.encode()).hexdigest()


# VULNERABILITY: No salt in password hashing
def hash_password_no_salt(password: str) -> str:
    """
    Hash password without salt - VULNERABLE.

    Without salt, identical passwords have identical hashes.
    """
    # BAD: No salt makes rainbow table attacks possible
    return hashlib.sha256(password.encode()).hexdigest()


# VULNERABILITY: Using DES encryption
def encrypt_des(data: str, key: bytes) -> bytes:
    """
    Encrypt with DES - VULNERABLE (weak encryption).

    DES has a 56-bit key which is too short.
    """
    # BAD: DES is deprecated
    from Crypto.Cipher import DES  # noqa

    cipher = DES.new(key[:8], DES.MODE_ECB)
    padded = data.ljust(8 * ((len(data) + 7) // 8))
    return cipher.encrypt(padded.encode())


# VULNERABILITY: ECB mode encryption
def encrypt_ecb(data: str, key: bytes) -> bytes:
    """
    Encrypt with ECB mode - VULNERABLE.

    ECB mode reveals patterns in encrypted data.
    """
    from Crypto.Cipher import AES  # noqa

    # BAD: ECB mode is insecure
    cipher = AES.new(key, AES.MODE_ECB)
    padded = data.ljust(16 * ((len(data) + 15) // 16))
    return cipher.encrypt(padded.encode())


# VULNERABILITY: Predictable random for security
def generate_token() -> str:
    """
    Generate auth token - VULNERABLE (predictable random).
    """
    import random

    # BAD: random module is not cryptographically secure
    token = ''.join(random.choices('abcdef0123456789', k=32))
    return token


# VULNERABILITY: Weak comparison for timing attacks
def verify_token(provided: str, stored: str) -> bool:
    """
    Verify token - VULNERABLE to timing attacks.
    """
    # BAD: Early return reveals length/content via timing
    if len(provided) != len(stored):
        return False

    for i in range(len(provided)):
        if provided[i] != stored[i]:
            return False

    return True


# SECURE EXAMPLE: Using bcrypt
def hash_password_secure(password: str) -> str:
    """
    Hash password with bcrypt - SECURE.
    """
    import bcrypt

    # GOOD: bcrypt with auto-generated salt
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()


# SECURE EXAMPLE: Constant-time comparison
def verify_token_secure(provided: str, stored: str) -> bool:
    """
    Verify token securely - SECURE.
    """
    import hmac

    # GOOD: Constant-time comparison
    return hmac.compare_digest(provided, stored)
