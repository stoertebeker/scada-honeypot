"""Persistenzschnittstellen fuer Zustand, Events und Outbox."""

from honeypot.storage.sqlite_store import SQLiteEventStore

__all__ = ["SQLiteEventStore"]
