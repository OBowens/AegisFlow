from pathlib import Path
from secrets import token_hex

from django.conf import settings
from django.core.files.storage import FileSystemStorage
from django.utils import timezone
from django.utils.text import get_valid_filename


def save_uploaded_log_file(uploaded_file, organization_id=None):
    logs_dir = Path(settings.PRIVATE_UPLOAD_ROOT) / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    original_name = get_valid_filename(Path(uploaded_file.name).name)
    stem = Path(original_name).stem or "uploaded_log"
    suffix = Path(original_name).suffix.lower()
    timestamp = timezone.now().strftime("%Y%m%d%H%M%S")
    random_suffix = token_hex(3)
    org_prefix = f"org{organization_id}_" if organization_id else ""
    stored_filename = f"{org_prefix}{stem}_{timestamp}_{random_suffix}{suffix}"

    storage = FileSystemStorage(location=str(logs_dir))
    saved_name = storage.save(stored_filename, uploaded_file)

    absolute_path = logs_dir / saved_name
    relative_path = Path("logs") / saved_name

    return saved_name, str(absolute_path), str(relative_path)
