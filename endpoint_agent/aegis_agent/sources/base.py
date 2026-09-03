"""The Event Log abstraction.

Everything the agent does downstream of this interface is plain data and
is fully tested on Linux. Only :class:`~aegis_agent.sources.windows.WindowsEventLogSource`
touches ``win32evtlog`` and needs a real Windows host to verify.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..events import EventRecord


class EventSource(ABC):
    @abstractmethod
    def read_new_events(self, bookmarks: dict[str, int]) -> list[EventRecord]:
        """Return records not yet seen, ascending by ``(channel, record_id)``.

        ``bookmarks`` maps a channel name to the highest ``record_id``
        already durably handled for it; the source must return only
        records strictly beyond that. An empty / missing entry means
        "everything currently available for that channel".
        """
        raise NotImplementedError
