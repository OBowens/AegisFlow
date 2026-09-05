import hashlib

from django.db import migrations


def hash_existing_item_keys(apps, schema_editor):
    """Convert any pre-change ChecklistItemState.item_key (the old
    normalized-then-truncated line text) to the SHA-256 digest the new
    apps.playbooks.services.text_parsing.checklist_item_key now returns.

    ChecklistItemState is empty when this ships, so in practice this is a
    no-op -- it exists so an environment that somehow has old plain-text
    keys converts cleanly rather than silently dropping those incidents'
    completion state on the first page render after the code change.

    Idempotent (skips rows that already hold a 64-char hex digest), so a
    partially-applied run is safe to resume. One known gap: for a source
    line that was longer than 300 characters the old key was truncated, so
    hashing that stored value cannot reproduce the digest of the full line
    -- that state is unrecoverable, which is the same collision/loss the
    truncation itself caused and the reason it's being removed.
    """
    ChecklistItemState = apps.get_model("playbooks", "ChecklistItemState")
    for state in ChecklistItemState.objects.all().iterator(chunk_size=500):
        value = state.item_key or ""
        if len(value) == 64 and all(char in "0123456789abcdef" for char in value):
            continue
        state.item_key = hashlib.sha256(value.encode("utf-8")).hexdigest()
        state.save(update_fields=["item_key"])


class Migration(migrations.Migration):
    dependencies = [("playbooks", "0003_checklistitemstate")]

    operations = [
        migrations.RunPython(hash_existing_item_keys, migrations.RunPython.noop),
    ]
