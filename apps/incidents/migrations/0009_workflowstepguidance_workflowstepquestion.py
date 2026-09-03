import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('incidents', '0008_add_workflow_state'),
    ]

    operations = [
        migrations.CreateModel(
            name='WorkflowStepGuidance',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('stage', models.CharField(max_length=20)),
                ('next_step_text', models.TextField()),
                ('model_used', models.CharField(blank=True, max_length=100)),
                ('generated_at', models.DateTimeField(auto_now_add=True)),
                ('incident', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='workflow_step_guidance', to='incidents.incidentgroup')),
            ],
            options={
                'ordering': ['-generated_at'],
            },
        ),
        migrations.CreateModel(
            name='WorkflowStepQuestion',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('stage', models.CharField(max_length=20)),
                ('question_text', models.TextField()),
                ('answer_text', models.TextField()),
                ('model_used', models.CharField(blank=True, max_length=100)),
                ('asked_at', models.DateTimeField(auto_now_add=True)),
                ('incident', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='workflow_step_questions', to='incidents.incidentgroup')),
            ],
            options={
                'ordering': ['asked_at'],
            },
        ),
    ]
