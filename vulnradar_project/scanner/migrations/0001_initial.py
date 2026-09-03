import uuid
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name='Scan',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('url', models.URLField(max_length=2048)),
                ('status', models.CharField(
                    choices=[
                        ('pending', 'Pending'),
                        ('running', 'Running'),
                        ('completed', 'Completed'),
                        ('failed', 'Failed'),
                    ],
                    default='pending',
                    max_length=20,
                )),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
        migrations.CreateModel(
            name='Finding',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('scan', models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='findings',
                    to='scanner.scan',
                )),
                ('category', models.CharField(max_length=100)),
                ('severity', models.CharField(
                    choices=[
                        ('critical', 'Critical'),
                        ('high', 'High'),
                        ('medium', 'Medium'),
                        ('low', 'Low'),
                        ('info', 'Info'),
                    ],
                    max_length=20,
                )),
                ('title', models.CharField(max_length=255)),
                ('description', models.TextField()),
                ('remediation', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
            ],
            options={
                'ordering': ['severity'],
            },
        ),
    ]
