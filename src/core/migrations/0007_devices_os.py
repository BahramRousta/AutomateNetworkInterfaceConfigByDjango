# Generated by Django 4.1.2 on 2022-10-29 11:30

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0006_alter_devices_mac_address'),
    ]

    operations = [
        migrations.AddField(
            model_name='devices',
            name='os',
            field=models.CharField(blank=True, max_length=200, null=True),
        ),
    ]
