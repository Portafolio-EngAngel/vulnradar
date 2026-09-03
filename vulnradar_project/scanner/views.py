from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponseNotAllowed
from django.urls import reverse

from .models import Scan, Finding
from .tasks import run_scan

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}


def index(request):
    return render(request, 'scanner/index.html')


def create_scan(request):
    if request.method != 'POST':
        return HttpResponseNotAllowed(['POST'])

    url = request.POST.get('url', '').strip()

    if not url:
        return render(request, 'scanner/index.html', {'error': 'Please provide a URL.'})

    # Ensure URL has a scheme
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    scan = Scan.objects.create(url=url, status='pending')
    run_scan.delay(str(scan.id))

    return redirect(reverse('scan_detail', kwargs={'scan_id': scan.id}))


def scan_detail(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)

    findings = sorted(
        scan.findings.all(),
        key=lambda f: SEVERITY_ORDER.get(f.severity, 99)
    )

    # Group findings by severity for display
    findings_by_severity = {}
    for finding in findings:
        findings_by_severity.setdefault(finding.severity, []).append(finding)

    # Count by severity
    severity_counts = {
        'critical': sum(1 for f in findings if f.severity == 'critical'),
        'high': sum(1 for f in findings if f.severity == 'high'),
        'medium': sum(1 for f in findings if f.severity == 'medium'),
        'low': sum(1 for f in findings if f.severity == 'low'),
        'info': sum(1 for f in findings if f.severity == 'info'),
    }

    is_in_progress = scan.status in ('pending', 'running')

    context = {
        'scan': scan,
        'findings': findings,
        'findings_by_severity': findings_by_severity,
        'severity_counts': severity_counts,
        'is_in_progress': is_in_progress,
        'total_findings': len(findings),
    }

    return render(request, 'scanner/scan_detail.html', context)
