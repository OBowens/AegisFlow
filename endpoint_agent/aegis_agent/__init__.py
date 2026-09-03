"""AegisFlow Windows endpoint agent (feature Part 2).

A standalone, dependency-free (on Linux; pywin32 only on Windows) process
that reads Windows Event Log entries for process creation (4688) and
PowerShell script-block logging (4104), suppresses known-safe noise
locally, buffers the rest durably, and ships it in batches to the
AegisFlow backend's ``POST /endpoints/api/ingest/`` endpoint.

It does NOT decide what is suspicious -- that is Part 3's job. This layer
only removes events that can be verified as uninteresting in isolation,
and logs every suppression with its reason.
"""

__version__ = "0.2.0"
