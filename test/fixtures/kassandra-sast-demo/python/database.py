"""
Database module with SQL Injection vulnerabilities.
CWE-89: SQL Injection
Severity: CRITICAL
"""

import sqlite3
from typing import Optional, List, Dict


def get_connection():
    """Get database connection."""
    return sqlite3.connect('app.db')


# VULNERABILITY: SQL Injection via string concatenation
def get_user_by_id(user_id: str) -> Optional[Dict]:
    """
    Get user by ID - VULNERABLE to SQL Injection.

    Example attack: user_id = "1 OR 1=1--"
    """
    conn = get_connection()
    cursor = conn.cursor()

    # BAD: Direct string concatenation
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)

    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


# VULNERABILITY: SQL Injection via f-string
def search_users(username: str) -> List[Dict]:
    """
    Search users by username - VULNERABLE to SQL Injection.

    Example attack: username = "'; DROP TABLE users;--"
    """
    conn = get_connection()
    cursor = conn.cursor()

    # BAD: f-string interpolation in SQL
    query = f"SELECT * FROM users WHERE username LIKE '%{username}%'"
    cursor.execute(query)

    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


# VULNERABILITY: SQL Injection via .format()
def authenticate_user(username: str, password: str) -> bool:
    """
    Authenticate user - VULNERABLE to SQL Injection.

    Example attack: username = "admin'--", password = "anything"
    """
    conn = get_connection()
    cursor = conn.cursor()

    # BAD: .format() in SQL query
    query = "SELECT * FROM users WHERE username = '{}' AND password = '{}'".format(
        username, password
    )
    cursor.execute(query)

    result = cursor.fetchone()
    conn.close()
    return result is not None


# VULNERABILITY: SQL Injection in ORDER BY clause
def get_users_sorted(sort_column: str, sort_order: str = "ASC") -> List[Dict]:
    """
    Get users with sorting - VULNERABLE to SQL Injection.

    Example attack: sort_column = "id; DROP TABLE users;--"
    """
    conn = get_connection()
    cursor = conn.cursor()

    # BAD: Unsanitized column name in ORDER BY
    query = f"SELECT * FROM users ORDER BY {sort_column} {sort_order}"
    cursor.execute(query)

    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


# SECURE EXAMPLE: Using parameterized queries
def get_user_secure(user_id: int) -> Optional[Dict]:
    """
    Get user by ID - SECURE version using parameterized query.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # GOOD: Parameterized query
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))

    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None
