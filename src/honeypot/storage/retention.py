"""Konfigurierbare Grenzen fuer persistente Honeypot-Belege."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SQLiteRetentionPolicy:
    """Harte und logische Grenzen fuer attacker-getriebene SQLite-Daten."""

    max_age_days: int = 30
    max_event_rows: int = 250_000
    max_event_rows_per_source: int = 25_000
    max_alert_rows: int = 50_000
    max_outbox_rows: int = 50_000
    max_campaign_rows: int = 10_000
    max_campaign_rows_per_source: int = 1_000
    max_credential_rows: int = 200_000
    max_unique_usernames: int = 100_000
    max_unique_usernames_per_source: int = 1_000
    max_database_bytes: int = 512 * 1024 * 1024
    reserved_health_bytes: int = 16 * 1024 * 1024
    min_free_bytes: int = 256 * 1024 * 1024
    sweep_interval_writes: int = 100

    def __post_init__(self) -> None:
        positive_fields = (
            "max_age_days",
            "max_event_rows",
            "max_event_rows_per_source",
            "max_alert_rows",
            "max_outbox_rows",
            "max_campaign_rows",
            "max_campaign_rows_per_source",
            "max_credential_rows",
            "max_unique_usernames",
            "max_unique_usernames_per_source",
            "max_database_bytes",
            "sweep_interval_writes",
        )
        for field_name in positive_fields:
            if getattr(self, field_name) <= 0:
                raise ValueError(f"{field_name} muss groesser als 0 sein")
        if self.reserved_health_bytes < 0:
            raise ValueError("reserved_health_bytes muss groesser oder gleich 0 sein")
        if self.min_free_bytes < 0:
            raise ValueError("min_free_bytes muss groesser oder gleich 0 sein")
        if self.reserved_health_bytes >= self.max_database_bytes:
            raise ValueError("reserved_health_bytes muss kleiner als max_database_bytes sein")
        if self.max_event_rows_per_source > self.max_event_rows:
            raise ValueError("max_event_rows_per_source darf max_event_rows nicht uebersteigen")
        if self.max_campaign_rows_per_source > self.max_campaign_rows:
            raise ValueError("max_campaign_rows_per_source darf max_campaign_rows nicht uebersteigen")
        if self.max_unique_usernames_per_source > self.max_unique_usernames:
            raise ValueError(
                "max_unique_usernames_per_source darf max_unique_usernames nicht uebersteigen"
            )


@dataclass(frozen=True, slots=True)
class JsonlRetentionPolicy:
    """Rotations- und Speichergrenzen fuer das optionale JSONL-Archiv."""

    max_file_bytes: int = 64 * 1024 * 1024
    max_total_bytes: int = 512 * 1024 * 1024
    max_age_days: int = 30
    min_free_bytes: int = 256 * 1024 * 1024

    def __post_init__(self) -> None:
        for field_name in ("max_file_bytes", "max_total_bytes", "max_age_days"):
            if getattr(self, field_name) <= 0:
                raise ValueError(f"{field_name} muss groesser als 0 sein")
        if self.min_free_bytes < 0:
            raise ValueError("min_free_bytes muss groesser oder gleich 0 sein")
        if self.max_file_bytes > self.max_total_bytes:
            raise ValueError("max_file_bytes darf max_total_bytes nicht uebersteigen")
