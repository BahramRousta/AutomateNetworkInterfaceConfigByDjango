# Generated by Django 4.1.2 on 2022-11-12 11:45

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0004_host_network_card_name'),
    ]

    operations = [
        migrations.CreateModel(
            name='FireWall',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('status', models.BooleanField(default=False)),
                ('reset', models.BooleanField(default=False)),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('updated', models.DateTimeField(auto_now=True)),
                ('allowed_port', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='allowed', to='core.port')),
                ('denied_port', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='denied', to='core.port')),
                ('host', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='firewall', to='core.host')),
                ('limited_port', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='limited', to='core.port')),
            ],
        ),
    ]
