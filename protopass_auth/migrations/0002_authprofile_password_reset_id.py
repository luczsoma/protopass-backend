# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2018-05-02 20:59
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('protopass_auth', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='authprofile',
            name='password_reset_id',
            field=models.CharField(max_length=128),
            preserve_default=False,
        ),
    ]