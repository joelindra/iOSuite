"""
Event Dispatcher & Queue Manager
Collects, deduplicates, and filters intercepted handler events in real-time.
Supports category isolation, regex/fuzzy search, and pinned bookmarks.
"""

import asyncio
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable, Set


@dataclass
class InterceptedEvent:
    id: str
    timestamp: str
    category: str
    action_type: str
    summary: str
    target_class: str = ""
    selector: str = ""
    target_pointer: str = "0x0"
    sender: Optional[Dict[str, Any]] = None
    location: Optional[Dict[str, Any]] = None
    backtrace: Optional[Dict[str, Any]] = None
    raw: Dict[str, Any] = field(default_factory=dict)
    hit_count: int = 1
    pinned: bool = False

    @property
    def time_str(self) -> str:
        try:
            # Parse ISO timestamp or fallback
            dt = datetime.fromisoformat(self.timestamp.replace("Z", "+00:00"))
            return dt.strftime("%H:%M:%S")
        except Exception:
            return self.timestamp[:8] if len(self.timestamp) >= 8 else self.timestamp

    @property
    def key(self) -> str:
        """Key used for deduplicating consecutive identical actions."""
        return f"{self.category}:{self.target_class}:{self.selector}:{self.action_type}:{self.summary}"


class EventDispatcher:
    """Manages event history, queueing, filtering, and subscriptions."""

    def __init__(self, max_events: int = 2000):
        self.max_events = max_events
        self.events: List[InterceptedEvent] = []
        self._listeners: List[Callable[[InterceptedEvent], None]] = []
        self._category_filters: Set[str] = set()
        self._search_query: str = ""
        self._pinned_only: bool = False
        self._paused: bool = False
        self._compiled_regex: Optional[re.Pattern] = None
        self._lock = asyncio.Lock()

    def add_listener(self, callback: Callable[[InterceptedEvent], None]) -> None:
        """Register a callback for new or updated events."""
        self._listeners.append(callback)

    def remove_listener(self, callback: Callable[[InterceptedEvent], None]) -> None:
        if callback in self._listeners:
            self._listeners.remove(callback)

    def set_paused(self, paused: bool) -> None:
        self._paused = paused

    @property
    def is_paused(self) -> bool:
        return self._paused

    def clear(self) -> None:
        self.events.clear()

    def set_category_filters(self, categories: Set[str]) -> None:
        self._category_filters = set(categories)

    def toggle_category_filter(self, category: str) -> bool:
        """Toggle a specific category on/off. Returns True if now active."""
        if category in self._category_filters:
            self._category_filters.remove(category)
            return False
        else:
            self._category_filters.add(category)
            return True

    def clear_category_filters(self) -> None:
        self._category_filters.clear()

    @property
    def category_filters(self) -> Set[str]:
        return set(self._category_filters)

    def set_pinned_only(self, pinned_only: bool) -> None:
        self._pinned_only = pinned_only

    @property
    def pinned_only(self) -> bool:
        return self._pinned_only

    def toggle_pin(self, event_id: str) -> bool:
        """Toggle pinned status for an event by ID. Returns updated pinned state."""
        for ev in self.events:
            if ev.id == event_id:
                ev.pinned = not ev.pinned
                return ev.pinned
        return False


    def set_search_query(self, query: str) -> None:
        self._search_query = query.strip()
        self._compiled_regex = None
        # Check if query is in /regex/ format
        if self._search_query.startswith("/") and len(self._search_query) > 1:
            pattern_str = self._search_query[1:]
            if pattern_str.endswith("/"):
                pattern_str = pattern_str[:-1]
            try:
                self._compiled_regex = re.compile(pattern_str, re.IGNORECASE)
            except re.error:
                self._compiled_regex = None

    def process_raw_event(self, raw_payload: Dict[str, Any]) -> Optional[InterceptedEvent]:
        """Convert a Frida event dict into an InterceptedEvent and handle deduplication."""
        if self._paused:
            return None

        event = InterceptedEvent(
            id=raw_payload.get("id", f"ev_{len(self.events)}"),
            timestamp=raw_payload.get("timestamp", datetime.now().isoformat()),
            category=raw_payload.get("category", "ui_action"),
            action_type=raw_payload.get("actionType", "action"),
            summary=raw_payload.get("summary", "Unknown Action"),
            target_class=raw_payload.get("targetClass", ""),
            selector=raw_payload.get("selector", ""),
            target_pointer=raw_payload.get("targetPointer", "0x0"),
            sender=raw_payload.get("sender"),
            location=raw_payload.get("location"),
            backtrace=raw_payload.get("backtrace"),
            raw=raw_payload,
            hit_count=1,
            pinned=raw_payload.get("pinned", False),
        )

        # Check for consecutive identical event to increment hit count
        if self.events and self.events[-1].key == event.key:
            last_event = self.events[-1]
            last_event.hit_count += 1
            last_event.timestamp = event.timestamp
            for listener in self._listeners:
                listener(last_event)
            return last_event

        self.events.append(event)
        if len(self.events) > self.max_events:
            self.events.pop(0)

        for listener in self._listeners:
            listener(event)

        return event

    def get_filtered_events(self) -> List[InterceptedEvent]:
        """Return events matching current category, search regex/fuzzy, and pinned filters."""
        result = []
        for ev in self.events:
            # Pinned only filter
            if self._pinned_only and not ev.pinned:
                continue

            # Category filter (if any are active)
            if self._category_filters and ev.category not in self._category_filters:
                continue

            # Search filter (Regex or Substring/Token matching)
            if self._search_query:
                combined_text = f"{ev.summary} {ev.target_class} {ev.selector} {ev.category} {ev.action_type}"
                if self._compiled_regex:
                    if not self._compiled_regex.search(combined_text):
                        continue
                else:
                    q_lower = self._search_query.lower()
                    # Multi-token matching (e.g. "pay btn")
                    tokens = q_lower.split()
                    c_lower = combined_text.lower()
                    if not all(tok in c_lower for tok in tokens):
                        continue

            result.append(ev)
        return result
