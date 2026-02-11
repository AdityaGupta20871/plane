# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("db", "0119_alter_estimatepoint_key"),
    ]

    operations = [
        migrations.AlterField(
            model_name="account",
            name="provider",
            field=models.CharField(
                choices=[
                    ("google", "Google"),
                    ("github", "Github"),
                    ("gitlab", "GitLab"),
                    ("oidc", "OIDC"),
                ]
            ),
        ),
    ]
