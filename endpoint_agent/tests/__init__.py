"""Test package bootstrap.

Ensures ``aegis_agent`` is importable no matter what directory the test
runner is invoked from (``python -m unittest discover`` inside
``endpoint_agent/`` already puts it on the path; this covers the rest).
"""

import logging
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# Keep expected warning/error log lines out of the test output. Tests
# that assert on logging use ``assertLogs``, which sets its own level on
# the target logger for its duration and is unaffected by this.
logging.getLogger("aegis_agent").setLevel(logging.CRITICAL)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
