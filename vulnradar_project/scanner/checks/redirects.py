import requests
from urllib.parse import urlparse

CATEGORY = 'Redirects'


def check_redirects(url: str) -> list[dict]:
    findings = []

    original_host = urlparse(url).netloc.lower()

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            verify=False
        )
    except Exception:
        return []

    # Build redirect chain from response history
    redirect_chain = [r.url for r in response.history] + [response.url]

    if len(redirect_chain) <= 1:
        return []

    final_url = response.url
    final_host = urlparse(final_url).netloc.lower()

    # Strip www. prefix for comparison
    def normalize_host(host: str) -> str:
        return host.removeprefix('www.')

    original_normalized = normalize_host(original_host)
    final_normalized = normalize_host(final_host)

    if original_normalized and final_normalized and original_normalized != final_normalized:
        chain_str = ' -> '.join(redirect_chain)
        findings.append({
            'category': CATEGORY,
            'severity': 'info',
            'title': 'Redirect Chain Leads to Different Domain',
            'description': (
                f'Requesting "{url}" resulted in a redirect to a different domain: "{final_url}". '
                f'Full redirect chain: {chain_str}. '
                'While often legitimate (e.g., www to non-www, CDN), cross-domain redirects '
                'can indicate open redirect vulnerabilities if the destination can be controlled '
                'by user input.'
            ),
            'remediation': (
                'Review your redirect configuration to ensure the destination domain is intentional '
                'and cannot be influenced by user-supplied input. '
                'Validate and whitelist redirect targets if redirects are driven by URL parameters.'
            ),
        })

    return findings
