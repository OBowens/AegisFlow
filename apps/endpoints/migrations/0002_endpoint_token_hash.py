"""Store only the SHA-256 hash of an endpoint's bearer token, never the
raw token.

The raw token has 256 bits of entropy (secrets.token_urlsafe(32)), so a
fast hash -- not a password KDF -- is enough: there is nothing to
brute-force, and this only needs to keep a database-only leak from
yielding working fleet credentials.

Safe as a plain RemoveField + AddField(unique): the endpoints feature is
new in this release and no ``Endpoint`` row exists in any deployed
database, so there is nothing to back-fill and no uniqueness collision to
resolve.
"""

import apps.endpoints.models
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('endpoints', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='endpoint',
            name='enrollment_token',
        ),
        migrations.AddField(
            model_name='endpoint',
            name='token_hash',
            field=models.CharField(
                default=apps.endpoints.models._default_token_hash,
                editable=False,
                max_length=64,
                unique=True,
            ),
        ),
    ]
