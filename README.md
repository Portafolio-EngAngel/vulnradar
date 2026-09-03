# VulnRadar — Automated Security Scanner

Scan any URL for security vulnerabilities across the OWASP Top 10. Async scanning with Celery, detailed findings report with severity ratings and remediation steps.

## Stack

| Layer | Technology |
|-------|-----------|
| Backend | Django 5.1 · Python 3.12 |
| Task Queue | Celery 5 · Redis 7 |
| Database | PostgreSQL 16 |
| Frontend | Django Templates · Tailwind CSS |
| Infrastructure | Docker Compose |

## Security Checks

| Category | What is checked |
|----------|----------------|
| Security Headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| SSL/TLS | HTTPS enforcement, redirect chain, certificate validity |
| Cookies | HttpOnly, Secure, SameSite flags |
| Information Disclosure | Server/X-Powered-By headers, exposed .env/.git paths |
| Redirects | Open redirect indicators |

## Quick Start

```bash
git clone https://github.com/EngAngel/vulnradar.git
cd vulnradar
docker compose up --build
# open http://localhost:8000
```

## Severity Levels

| Level | Color | Meaning |
|-------|-------|---------|
| Critical | Red | Immediate action required |
| High | Orange | Fix as soon as possible |
| Medium | Yellow | Fix in next release |
| Low | Blue | Fix when convenient |
| Info | Gray | Informational only |
