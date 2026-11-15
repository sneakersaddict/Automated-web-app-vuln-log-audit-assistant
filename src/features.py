import re
_REQ = re.compile(r'"(.*)"\s+\d{3}\s+\d+\s*$')

def request_text(line):
    """Keep only 'METHOD path?query HTTP/1.1' from an Apache-style log line."""
    m = _REQ.search(line)
    return m.group(1) if m else line
