#!/usr/bin/env python
import os
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


def add_local_vendor_paths() -> None:
    for vendor_name in (".vendor_pkgs", ".vendor_lib", ".vendor"):
        vendor_dir = BASE_DIR / vendor_name
        if vendor_dir.exists():
            sys.path.insert(0, str(vendor_dir))


def main() -> None:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        add_local_vendor_paths()
        try:
            from django.core.management import execute_from_command_line
        except ImportError:
            raise ImportError(
                "Django is not installed. Add it to the environment or the local vendor fallback directories."
            ) from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
