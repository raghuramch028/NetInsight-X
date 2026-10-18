from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dashboard", "0008_packet_threat_label_and_qos_bounds"),
    ]

    operations = [
        migrations.AddField(
            model_name="flowrecord",
            name="simulated_policy_action",
            field=models.CharField(default="MONITOR", max_length=32),
        ),
        migrations.AddField(
            model_name="flowrecord",
            name="simulated_reclaimed_bps",
            field=models.FloatField(default=0.0),
        ),
    ]
