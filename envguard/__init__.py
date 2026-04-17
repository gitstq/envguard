"""
EnvGuard - Environment Variable Security Auditor

A zero-dependency CLI tool to detect sensitive information leaks in .env files.
"""

__version__ = "1.0.0"
__author__ = "gitstq"

from envguard.scanner import EnvScanner
from envguard.rules import SecurityRules, Severity
from envguard.reporter import Reporter

__all__ = [
    "EnvScanner",
    "SecurityRules", 
    "Severity",
    "Reporter",
]
