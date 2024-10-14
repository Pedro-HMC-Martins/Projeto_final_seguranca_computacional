SQL_INJECTION_PATTERNS = [
    r'(\bor\b|\band\b).*(=|like)',        # Use of 'OR', 'AND' with operators
    r'(\bunion\b|\bselect\b|\binsert\b|\bdelete\b|\bdrop\b)',  # SQL keywords
    r'(--|#)',                            # SQL comments
]

XSS_PATTERNS = [
    r'(<script.*?>.*?</script>)',         # HTML script tags
    r'javascript:.*',                     # JavaScript URLs
    r'(\bon\w+?\s*=\s*".*?")',            # HTML event attributes
]

COMMAND_INJECTION_PATTERNS = [
    r'(;|\||\&\&|\|\|)\s*(cd|ls|echo|set|unset|export|cat|chmod|curl|wget|ping|netstat|ps|kill|uname|whoami|script|perl|python|ruby|bash|sh|sudo)\b',
    r'\b(exec|system|bash|sh|cmd|cat|ping|uname)\s*\('
]
