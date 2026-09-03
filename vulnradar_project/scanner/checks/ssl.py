import requests
from urllib.parse import urlparse

CATEGORY = 'SSL/TLS'


def check_ssl(url: str) -> list[dict]:
    findings = []
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()

    # Finding: site uses plain HTTP, not HTTPS
    if scheme == 'http':
        findings.append({
            'category': CATEGORY,
            'severity': 'high',
            'title': 'Site Not Using HTTPS',
            'description': (
                f'The target URL uses plain HTTP ({url}). '
                'All data transmitted over HTTP is unencrypted and can be intercepted '
                'by network attackers (man-in-the-middle attacks).'
            ),
            'remediation': (
                'Obtain a TLS certificate (e.g., from Let\'s Encrypt) and serve all content '
                'over HTTPS. Redirect all HTTP traffic to HTTPS permanently (301).'
            ),
        })

        # Check if HTTP redirects to HTTPS
        http_url = url
        try:
            response = requests.get(
                http_url,
                timeout=10,
                allow_redirects=True,
                verify=False
            )
            final_url = response.url
            final_scheme = urlparse(final_url).scheme.lower()

            if final_scheme != 'https':
                findings.append({
                    'category': CATEGORY,
                    'severity': 'high',
                    'title': 'HTTP Does Not Redirect to HTTPS',
                    'description': (
                        f'The server at {http_url} does not redirect HTTP traffic to HTTPS. '
                        f'The final URL after redirects is: {final_url}. '
                        'Users accessing the site over HTTP will not be automatically protected.'
                    ),
                    'remediation': (
                        'Configure your web server to issue a 301 redirect from all '
                        'HTTP requests to the equivalent HTTPS URL. '
                        'In Nginx: return 301 https://$host$request_uri;'
                    ),
                })
        except Exception:
            pass

    # Check if HTTPS is functional
    https_url = url.replace('http://', 'https://', 1) if scheme == 'http' else url
    if not https_url.startswith('https://'):
        https_url = 'https://' + parsed.netloc + parsed.path

    try:
        requests.get(https_url, timeout=10, allow_redirects=True, verify=True)
        # HTTPS works fine — no finding
    except requests.exceptions.SSLError:
        findings.append({
            'category': CATEGORY,
            'severity': 'critical',
            'title': 'SSL/TLS Certificate Error',
            'description': (
                f'An SSL/TLS error occurred when connecting to {https_url}. '
                'The certificate may be expired, self-signed, or for a different domain. '
                'Browsers will display security warnings, and users may be vulnerable to MITM attacks.'
            ),
            'remediation': (
                'Ensure your TLS certificate is valid, not expired, issued by a trusted CA, '
                'and matches the domain name. Use Let\'s Encrypt for free, auto-renewed certificates.'
            ),
        })
    except requests.exceptions.ConnectionError:
        findings.append({
            'category': CATEGORY,
            'severity': 'critical',
            'title': 'HTTPS Not Available',
            'description': (
                f'The server does not appear to support HTTPS at {https_url}. '
                'Connections over HTTPS failed entirely, meaning the site cannot '
                'provide encrypted communication to its users.'
            ),
            'remediation': (
                'Configure your web server to listen on port 443 and install a valid TLS certificate. '
                'Services like Let\'s Encrypt provide free certificates with automated renewal.'
            ),
        })
    except Exception:
        pass

    return findings
