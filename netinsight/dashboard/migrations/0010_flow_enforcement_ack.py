from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("dashboard", "0009_flow_simulated_policy"),
    ]

    operations = [
        migrations.RenameField(
            model_name="flowrecord",
            old_name="simulated_policy_action",
            new_name="policy_action",
        ),
        migrations.RenameField(
            model_name="flowrecord",
            old_name="simulated_reclaimed_bps",
            new_name="policy_estimated_reclaimed_bps",
        ),
        migrations.AddField(
            model_name="agent",
            name="active_flow_blocks",
            field=models.JSONField(default=list),
        ),
    ]
