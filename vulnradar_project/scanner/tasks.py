import logging

from celery import shared_task
from django.utils import timezone

from .models import Scan, Finding

logger = logging.getLogger(__name__)
from .checks.headers import check_headers
from .checks.ssl import check_ssl
from .checks.cookies import check_cookies
from .checks.information_disclosure import check_information_disclosure
from .checks.redirects import check_redirects


@shared_task(bind=True, max_retries=0)
def run_scan(self, scan_id):
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        return

    scan.status = 'running'
    scan.save(update_fields=['status'])

    try:
        findings = []
        findings += check_headers(scan.url)
        findings += check_ssl(scan.url)
        findings += check_cookies(scan.url)
        findings += check_information_disclosure(scan.url)
        findings += check_redirects(scan.url)

        Finding.objects.bulk_create([
            Finding(scan=scan, **f) for f in findings
        ])

        scan.status = 'completed'
        scan.completed_at = timezone.now()
    except Exception as e:
        logger.exception("Scan %s failed: %s", scan_id, e)
        scan.status = 'failed'

    scan.save()
