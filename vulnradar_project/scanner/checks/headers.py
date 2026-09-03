import requests

CATEGORY = 'Security Headers'


def check_headers(url: str) -> list[dict]:
    findings = []

    try:
        response = requests.get(url, timeout=10, allow_redirects=True, verify=True)
        headers = {k.lower(): v for k, v in response.headers.items()}
    except Exception:
        return []

    # Content-Security-Policy — missing = high
    if 'content-security-policy' not in headers:
        findings.append({
            'category': CATEGORY,
            'severity': 'high',
            'title': 'Missing Content-Security-Policy Header',
            'description': (
                'The Content-Security-Policy (CSP) header is not set. '
                'CSP helps prevent cross-site scripting (XSS) and data injection attacks '
                'by specifying which dynamic resources are allowed to load.'
            ),
            'remediation': (
                'Add a Content-Security-Policy header to your HTTP responses. '
                "Example: Content-Security-Policy: default-src 'self'; "
                "script-src 'self'; object-src 'none'."
            ),
        })

    # Strict-Transport-Security — missing = high
    if 'strict-transport-security' not in headers:
        findings.append({
            'category': CATEGORY,
            'severity': 'high',
            'title': 'Missing Strict-Transport-Security (HSTS) Header',
            'description': (
                'The Strict-Transport-Security header is absent. '
                'Without HSTS, browsers may connect over insecure HTTP, '
                'exposing users to protocol downgrade attacks and cookie hijacking.'
            ),
            'remediation': (
                'Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload. '
                'Ensure your site fully supports HTTPS before enabling preload.'
            ),
        })

    # X-Frame-Options — missing = medium
    if 'x-frame-options' not in headers:
        findings.append({
            'category': CATEGORY,
            'severity': 'medium',
            'title': 'Missing X-Frame-Options Header',
            'description': (
                'The X-Frame-Options header is not present. '
                'This makes the site potentially vulnerable to clickjacking attacks, '
                'where an attacker loads your page inside an iframe to trick users.'
            ),
            'remediation': (
                "Add: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN. "
                'Alternatively, use the frame-ancestors CSP directive.'
            ),
        })

    # X-Content-Type-Options — missing = medium
    if 'x-content-type-options' not in headers:
        findings.append({
            'category': CATEGORY,
            'severity': 'medium',
            'title': 'Missing X-Content-Type-Options Header',
            'description': (
                'The X-Content-Type-Options header is not set. '
                'Without it, browsers may MIME-sniff a response away from the declared content type, '
                'enabling certain attack vectors like MIME confusion attacks.'
            ),
            'remediation': (
                'Add: X-Content-Type-Options: nosniff to all HTTP responses.'
            ),
        })

    # Referrer-Policy — missing = low
    if 'referrer-policy' not in headers:
        findings.append({
            'category': CATEGORY,
            'severity': 'low',
            'title': 'Missing Referrer-Policy Header',
            'description': (
                'The Referrer-Policy header is absent. '
                'Without it, the browser may send full URLs in the Referer header to third parties, '
                'potentially leaking sensitive URL parameters or paths.'
            ),
            'remediation': (
                'Add: Referrer-Policy: strict-origin-when-cross-origin or no-referrer-when-downgrade.'
            ),
        })

    # Permissions-Policy — missing = low
    if 'permissions-policy' not in headers:
        findings.append({
            'category': CATEGORY,
            'severity': 'low',
            'title': 'Missing Permissions-Policy Header',
            'description': (
                'The Permissions-Policy header (formerly Feature-Policy) is not set. '
                'This header controls which browser features and APIs can be used '
                'in the document and embedded iframes.'
            ),
            'remediation': (
                'Add a Permissions-Policy header to restrict access to browser features. '
                'Example: Permissions-Policy: camera=(), microphone=(), geolocation=().'
            ),
        })

    # Server header exposure — info
    server = headers.get('server', '')
    if server:
        findings.append({
            'category': 'Information Disclosure',
            'severity': 'info',
            'title': 'Server Header Exposes Software Information',
            'description': (
                f'The Server header is present and reveals: "{server}". '
                'Exposing server software and version information aids attackers '
                'in identifying known vulnerabilities for targeted exploitation.'
            ),
            'remediation': (
                'Configure your web server to suppress or anonymize the Server header. '
                'In Nginx: server_tokens off; In Apache: ServerTokens Prod; ServerSignature Off.'
            ),
        })

    # X-Powered-By exposure — info
    powered_by = headers.get('x-powered-by', '')
    if powered_by:
        findings.append({
            'category': 'Information Disclosure',
            'severity': 'info',
            'title': 'X-Powered-By Header Exposes Technology Stack',
            'description': (
                f'The X-Powered-By header reveals: "{powered_by}". '
                'This discloses the backend technology stack, giving attackers '
                'a head start in identifying applicable exploits.'
            ),
            'remediation': (
                'Remove the X-Powered-By header. '
                'In Express.js: app.disable("x-powered-by"). '
                'In PHP: expose_php = Off in php.ini.'
            ),
        })

    return findings
