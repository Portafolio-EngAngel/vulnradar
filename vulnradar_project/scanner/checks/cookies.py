import requests
from urllib.parse import urlparse

CATEGORY = 'Cookies'


def _parse_cookie_attributes(cookie_string: str) -> dict:
    """Parse a Set-Cookie header value into a dict of attributes."""
    parts = [p.strip() for p in cookie_string.split(';')]
    attributes = {}
    # First part is name=value
    if parts:
        name_value = parts[0]
        name = name_value.split('=')[0].strip()
        attributes['name'] = name

    for part in parts[1:]:
        lower = part.lower()
        if '=' in part:
            key, val = part.split('=', 1)
            attributes[key.strip().lower()] = val.strip()
        else:
            attributes[lower] = True

    return attributes


def check_cookies(url: str) -> list[dict]:
    findings = []

    try:
        response = requests.get(url, timeout=10, allow_redirects=True, verify=True)
    except Exception:
        return []

    is_https = urlparse(response.url).scheme.lower() == 'https'

    # Collect all Set-Cookie headers
    set_cookie_headers = []
    for header_name, header_value in response.headers.items():
        if header_name.lower() == 'set-cookie':
            set_cookie_headers.append(header_value)

    # requests merges duplicate headers; use raw response headers if available
    # Also check via requests' built-in cookies
    seen_cookies = set()

    for cookie_str in set_cookie_headers:
        attrs = _parse_cookie_attributes(cookie_str)
        cookie_name = attrs.get('name', 'unknown')

        if cookie_name in seen_cookies:
            continue
        seen_cookies.add(cookie_name)

        # Missing HttpOnly — medium
        if 'httponly' not in attrs:
            findings.append({
                'category': CATEGORY,
                'severity': 'medium',
                'title': f'Cookie "{cookie_name}" Missing HttpOnly Flag',
                'description': (
                    f'The cookie "{cookie_name}" does not have the HttpOnly flag set. '
                    'Without this flag, the cookie is accessible to JavaScript, '
                    'making it vulnerable to theft via cross-site scripting (XSS) attacks.'
                ),
                'remediation': (
                    f'Set the HttpOnly attribute on the "{cookie_name}" cookie. '
                    'Example: Set-Cookie: sessionid=abc123; HttpOnly; Secure; SameSite=Strict'
                ),
            })

        # Missing Secure flag (only meaningful on HTTPS) — medium
        if is_https and 'secure' not in attrs:
            findings.append({
                'category': CATEGORY,
                'severity': 'medium',
                'title': f'Cookie "{cookie_name}" Missing Secure Flag',
                'description': (
                    f'The cookie "{cookie_name}" does not have the Secure flag set. '
                    'Without Secure, the cookie can be transmitted over unencrypted HTTP connections, '
                    'exposing it to network interception.'
                ),
                'remediation': (
                    f'Add the Secure flag to the "{cookie_name}" cookie to ensure it is only '
                    'sent over HTTPS connections. '
                    'Example: Set-Cookie: sessionid=abc123; Secure; HttpOnly'
                ),
            })

        # Missing SameSite — low
        if 'samesite' not in attrs:
            findings.append({
                'category': CATEGORY,
                'severity': 'low',
                'title': f'Cookie "{cookie_name}" Missing SameSite Attribute',
                'description': (
                    f'The cookie "{cookie_name}" does not specify a SameSite attribute. '
                    'Without SameSite, the cookie may be sent with cross-site requests, '
                    'potentially enabling Cross-Site Request Forgery (CSRF) attacks.'
                ),
                'remediation': (
                    f'Add SameSite=Strict or SameSite=Lax to the "{cookie_name}" cookie. '
                    'Example: Set-Cookie: sessionid=abc123; SameSite=Strict; HttpOnly; Secure'
                ),
            })

    return findings
