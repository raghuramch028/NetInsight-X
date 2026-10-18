from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dashboard", "0010_flow_enforcement_ack"),
    ]

    operations = [
        migrations.AddField(
            model_name="flowrecord",
            name="classification_engine",
            field=models.CharField(default="Unknown", max_length=64),
        ),
        migrations.AddField(
            model_name="flowrecord",
            name="classification_confidence",
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="flowrecord",
            name="demo_event_id",
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
        migrations.AddField(
            model_name="flowrecord",
            name="first_src_ip",
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="flowrecord",
            name="first_src_port",
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="flowrecord",
            name="first_dst_ip",
            field=models.GenericIPAddressField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="flowrecord",
            name="first_dst_port",
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="agent",
            name="flow_enforcement_capable",
            field=models.BooleanField(default=False),
        ),
    ]
