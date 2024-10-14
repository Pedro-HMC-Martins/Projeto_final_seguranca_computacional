import re
from utils.patterns import *

def is_sql_injection(input_str):
    """Check if the input matches SQL injection patterns."""
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, input_str, re.IGNORECASE):
            print('SQL Injection detected:', input_str)
            return True
    return False

def is_xss_attempt(input_str):
    """Check if the input matches XSS patterns."""
    for pattern in XSS_PATTERNS:
        if re.search(pattern, input_str, re.IGNORECASE):
            print('XSS Attempt detected:', input_str)
            return True
    return False

def is_command_injection(input_str):
    """Check if the input matches command injection patterns."""
    for pattern in COMMAND_INJECTION_PATTERNS:
        if re.search(pattern, input_str, re.IGNORECASE):
            print('Command Injection detected:', input_str)
            return True
    return False

