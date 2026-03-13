"""Findings table widgets exposed as a stable dashboard API."""

from __future__ import annotations

from dips.gui.widgets import FindingsTable


class FindingsTableWidget(FindingsTable):
    """Named wrapper around the sortable findings table."""


__all__ = ["FindingsTableWidget"]
