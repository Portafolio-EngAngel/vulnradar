from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('scans/', views.create_scan, name='create_scan'),
    path('scans/<uuid:scan_id>/', views.scan_detail, name='scan_detail'),
]
