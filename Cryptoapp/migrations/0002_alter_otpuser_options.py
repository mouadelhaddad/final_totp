# Generated by Django 3.2.3 on 2021-12-16 20:30

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('Cryptoapp', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='otpuser',
            options={'ordering': ['username'], 'verbose_name': 'user'},
        ),
    ]