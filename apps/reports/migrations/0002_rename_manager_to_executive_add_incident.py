from django.db import migrations, models


NEW_CHOICES = [
    ('executive', 'Executive'),
    ('technical', 'Technical'),
    ('incident', 'Incident'),
    ('risk', 'Risk'),
    ('readiness', 'Readiness'),
    ('upload_summary', 'Upload Summary'),
    ('action_plan', 'Action Plan'),
]

OLD_CHOICES = [
    ('manager', 'Manager'),
    ('technical', 'Technical'),
    ('risk', 'Risk'),
    ('readiness', 'Readiness'),
    ('action_plan', 'Action Plan'),
]


def forwards_reclassify_manager_reports(apps, schema_editor):
    # Existing report_type="manager" rows were all created by the
    # deterministic, upload-scoped create_manager_report_for_upload
    # (apps/reports/services/generator.py) -- they are NOT the same thing
    # as the new on-demand, organization-wide Executive report, so they
    # are reclassified to the new upload_summary type rather than
    # following the field rename to "executive" (see the 2026-08-27
    # investigation into this exact naming collision).
    GeneratedReport = apps.get_model('reports', 'GeneratedReport')
    GeneratedReport.objects.filter(report_type='manager').update(report_type='upload_summary')


def backwards_reclassify_upload_summary_reports(apps, schema_editor):
    # Collapse everything the old schema has no room for back onto
    # 'manager' so the reverse migration leaves valid old-choice data.
    GeneratedReport = apps.get_model('reports', 'GeneratedReport')
    GeneratedReport.objects.filter(
        report_type__in=['upload_summary', 'executive', 'incident']
    ).update(report_type='manager')


class Migration(migrations.Migration):

    dependencies = [
        ('reports', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='generatedreport',
            name='report_type',
            field=models.CharField(choices=NEW_CHOICES, default='executive', max_length=20),
        ),
        migrations.RunPython(
            forwards_reclassify_manager_reports,
            backwards_reclassify_upload_summary_reports,
        ),
    ]
