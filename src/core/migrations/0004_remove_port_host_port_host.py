# Generated by Django 4.1.2 on 2022-11-12 17:54

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0003_alter_port_state'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='port',
            name='host',
        ),
        migrations.AddField(
            model_name='port',
            name='host',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, related_name='ports', to='core.host'),
            preserve_default=False,
        ),
    ]
