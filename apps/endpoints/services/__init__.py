"""Endpoint domain services.

``enroll_endpoint`` / ``resolve_available_name`` (Part 1) are re-exported
here so existing imports of ``apps.endpoints.services`` keep working now
that this is a package rather than a single module.
"""

from .enrollment import EnrollmentResult, enroll_endpoint, resolve_available_name

__all__ = ["EnrollmentResult", "enroll_endpoint", "resolve_available_name"]
