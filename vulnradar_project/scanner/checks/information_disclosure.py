import requests
from urllib.parse import urlparse, urljoin
import re

CATEGORY = 'Information Disclosure'

# Common debug/sensitive paths to probe
SENSITIVE_PATHS = [
    '/.env',
    '/.git/HEAD',
    '/phpinfo.php',
]

# Patterns that suggest a specific software/version is being revealed
SERVER_VERSION_PATTERN = re.compile(
    r'(apache|nginx|iis|lighttpd|gunicorn|uvicorn|werkzeug|tornado|express|tomcat|jetty)[/\s][\d.]+',
    re.IGNORECASE
)


def _base_url(url: str) -> str:
    """Return scheme + host only."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def check_information_disclosure(url: str) -> list[dict]:
    findings = []

    try:
        response = requests.get(url, timeout=10, allow_redirects=True, verify=True)
        headers = {k.lower(): v for k, v in response.headers.items()}
    except Exception:
        return []

    # Server header — check for version disclosure
    server = headers.get('server', '')
    if server and SERVER_VERSION_PATTERN.search(server):
        findings.append({
            'category': CATEGORY,
            'severity': 'info',
            'title': 'Server Header Reveals Software Version',
            'description': (
                f'The Server response header discloses specific software and version: "{server}". '
                'Version information helps attackers look up known CVEs and target '
                'unpatched vulnerabilities in the identified software.'
            ),
            'remediation': (
                'Configure your web server to suppress version information. '
                'Nginx: set server_tokens off; '
                'Apache: ServerTokens Prod and ServerSignature Off; '
                'Gunicorn/uWSGI: use a reverse proxy that strips this header.'
            ),
        })

    # X-Powered-By header
    powered_by = headers.get('x-powered-by', '')
    if powered_by:
        findings.append({
            'category': CATEGORY,
            'severity': 'info',
            'title': 'X-Powered-By Header Discloses Backend Technology',
            'description': (
                f'The X-Powered-By header is present with value: "{powered_by}". '
                'This header reveals the backend framework or runtime, '
                'which can be used to target framework-specific vulnerabilities.'
            ),
            'remediation': (
                'Disable the X-Powered-By header at the framework or server level. '
                'Express.js: app.disable("x-powered-by"); '
                'PHP: expose_php = Off in php.ini; '
                'ASP.NET: remove via web.config customHeaders.'
            ),
        })

    # Probe sensitive paths
    base = _base_url(url)
    for path in SENSITIVE_PATHS:
        probe_url = urljoin(base + '/', path.lstrip('/'))
        try:
            probe_resp = requests.get(
                probe_url,
                timeout=10,
                allow_redirects=False,
                verify=True
            )
            if probe_resp.status_code == 200:
                findings.append({
                    'category': CATEGORY,
                    'severity': 'critical',
                    'title': f'Sensitive File Exposed: {path}',
                    'description': (
                        f'The path {probe_url} returned HTTP 200 and is publicly accessible. '
                        f'"{path}" is a sensitive file that should never be served over HTTP. '
                        'This may expose environment variables, credentials, source control data, '
                        'or PHP debug information to unauthenticated attackers.'
                    ),
                    'remediation': (
                        f'Immediately block access to "{path}" at the web server level '
                        'and verify no sensitive data has been exfiltrated. '
                        'For .env files: never place them in the web root. '
                        'For .git/: add deny rules in Nginx/Apache for /.git/ paths. '
                        'For phpinfo.php: delete the file from production servers.'
                    ),
                })
        except Exception:
            continue

    return findings
