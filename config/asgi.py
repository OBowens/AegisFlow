import os
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


def add_local_vendor_paths() -> None:
    for vendor_name in (".vendor_pkgs", ".vendor_lib", ".vendor"):
        vendor_dir = BASE_DIR / vendor_name
        if vendor_dir.exists():
            sys.path.insert(0, str(vendor_dir))


try:
    from django.core.asgi import get_asgi_application
except ImportError:
    add_local_vendor_paths()
    from django.core.asgi import get_asgi_application


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

application = get_asgi_application()
