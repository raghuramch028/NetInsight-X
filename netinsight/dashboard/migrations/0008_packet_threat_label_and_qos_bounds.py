from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dashboard", "0007_systemsettings_llm_confidence_threshold_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="packetrecord",
            name="threat_label",
            field=models.CharField(blank=True, default=None, max_length=100, null=True),
        ),
        migrations.AddField(
            model_name="agent",
            name="current_throughput",
            field=models.FloatField(default=0.0),
        ),
        migrations.AddField(
            model_name="agent",
            name="throughput_sampled_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="systemsettings",
            name="qos_min_bandwidth",
            field=models.JSONField(default=list),
        ),
        migrations.AddField(
            model_name="systemsettings",
            name="qos_max_bandwidth",
            field=models.JSONField(default=list),
        ),
    ]
