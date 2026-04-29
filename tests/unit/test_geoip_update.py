from __future__ import annotations

from datetime import UTC, datetime
import gzip
import io
import json
from pathlib import Path
import urllib.error

from honeypot.geoip_update import (
    DBIP_ATTRIBUTION_LABEL,
    DBIP_ATTRIBUTION_URL,
    DBIP_LICENSE_NAME,
    update_dbip_lite,
)


class FakeResponse(io.BytesIO):
    def __init__(self, payload: bytes) -> None:
        super().__init__(payload)
        self.headers = {"Last-Modified": "Wed, 01 Apr 2026 06:54:00 GMT"}

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


def test_update_dbip_lite_downloads_country_and_asn_and_writes_cc_by_metadata(tmp_path: Path) -> None:
    requested_urls: list[str] = []

    def opener(request, *, timeout):
        del timeout
        requested_urls.append(request.full_url)
        return FakeResponse(gzip.compress(_mmdb_payload(request.full_url)))

    results = update_dbip_lite(
        target_dir=tmp_path,
        now=datetime(2026, 4, 29, tzinfo=UTC),
        opener=opener,
    )

    assert {result.name for result in results} == {"country", "asn"}
    assert (tmp_path / "dbip-country-lite.mmdb").read_bytes() == _mmdb_payload(requested_urls[0])
    assert (tmp_path / "dbip-asn-lite.mmdb").read_bytes() == _mmdb_payload(requested_urls[1])
    metadata = json.loads((tmp_path / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["provider"] == "DB-IP Lite"
    assert metadata["license"] == DBIP_LICENSE_NAME
    assert metadata["attribution"] == {
        "label": DBIP_ATTRIBUTION_LABEL,
        "url": DBIP_ATTRIBUTION_URL,
    }
    assert {dataset["name"] for dataset in metadata["datasets"]} == {"country", "asn"}
    assert all(dataset["release"] == "2026-04" for dataset in metadata["datasets"])


def test_update_dbip_lite_falls_back_to_previous_month_when_current_release_is_missing(tmp_path: Path) -> None:
    requested_urls: list[str] = []

    def opener(request, *, timeout):
        del timeout
        requested_urls.append(request.full_url)
        if "2026-05" in request.full_url:
            raise urllib.error.HTTPError(request.full_url, 404, "Not Found", hdrs=None, fp=None)
        return FakeResponse(gzip.compress(_mmdb_payload(request.full_url)))

    results = update_dbip_lite(
        target_dir=tmp_path,
        now=datetime(2026, 5, 1, tzinfo=UTC),
        opener=opener,
    )

    assert any("2026-05" in url for url in requested_urls)
    assert all(result.release == "2026-04" for result in results)
    metadata = json.loads((tmp_path / "metadata.json").read_text(encoding="utf-8"))
    assert all(dataset["release"] == "2026-04" for dataset in metadata["datasets"])


def test_update_dbip_lite_optional_mode_does_not_block_without_downloads(tmp_path: Path) -> None:
    def opener(request, *, timeout):
        del timeout
        raise urllib.error.HTTPError(request.full_url, 404, "Not Found", hdrs=None, fp=None)

    results = update_dbip_lite(
        target_dir=tmp_path,
        release="2026-04",
        optional=True,
        opener=opener,
    )

    assert results == ()
    assert not (tmp_path / "metadata.json").exists()


def _mmdb_payload(seed: str) -> bytes:
    return (f"MMDB:{seed}\n".encode("ascii") * 128)[:2048]
