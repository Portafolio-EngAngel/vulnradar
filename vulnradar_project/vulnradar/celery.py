import os
from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vulnradar.settings')

app = Celery('vulnradar')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks()
