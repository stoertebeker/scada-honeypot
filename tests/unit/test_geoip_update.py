from __future__ import annotations

from datetime import UTC, datetime
import gzip
import hashlib
import io
import json
from pathlib import Path
import urllib.error

import pytest

from honeypot.geoip_update import (
    DBIP_ATTRIBUTION_LABEL,
    DBIP_ATTRIBUTION_URL,
    DBIP_EGRESS_TARGET_SPEC,
    DBIP_LICENSE_NAME,
    GeoIpDownloadLimits,
    GeoIpUpdateError,
    _RejectRedirectHandler,
    main as geoip_main,
    update_dbip_lite,
)


class FakeResponse(io.BytesIO):
    def __init__(
        self,
        payload: bytes,
        *,
        clock: FakeClock | None = None,
        content_length: int | None = None,
    ) -> None:
        super().__init__(payload)
        self.headers = {
            "Content-Length": str(len(payload) if content_length is None else content_length),
            "Last-Modified": "Wed, 01 Apr 2026 06:54:00 GMT",
        }
        self._clock = clock

    def read(self, size: int = -1) -> bytes:
        if self._clock is not None:
            self._clock.advance(2.0)
        return super().read(size)

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


class FakeClock:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def advance(self, seconds: float) -> None:
        self.value += seconds


def test_update_dbip_lite_downloads_pinned_country_and_asn_and_writes_metadata(
    tmp_path: Path,
) -> None:
    requested_urls: list[str] = []
    archives = {
        "country": gzip.compress(_mmdb_payload("country"), mtime=0),
        "asn": gzip.compress(_mmdb_payload("asn"), mtime=0),
    }

    def opener(request, *, timeout):
        del timeout
        requested_urls.append(request.full_url)
        dataset = "country" if "country" in request.full_url else "asn"
        return FakeResponse(archives[dataset])

    results = update_dbip_lite(
        target_dir=tmp_path,
        release="2026-04",
        expected_sha256=_checksums(archives),
        now=datetime(2026, 4, 29, tzinfo=UTC),
        opener=opener,
        mmdb_validator=lambda path, dataset: None,
    )

    assert {result.name for result in results} == {"country", "asn"}
    assert (tmp_path / "dbip-country-lite.mmdb").read_bytes() == _mmdb_payload("country")
    assert (tmp_path / "dbip-asn-lite.mmdb").read_bytes() == _mmdb_payload("asn")
    metadata = json.loads((tmp_path / "metadata.json").read_text(encoding="utf-8"))
    assert metadata["provider"] == "DB-IP Lite"
    assert metadata["license"] == DBIP_LICENSE_NAME
    assert metadata["attribution"] == {
        "label": DBIP_ATTRIBUTION_LABEL,
        "url": DBIP_ATTRIBUTION_URL,
    }
    assert {dataset["name"] for dataset in metadata["datasets"]} == {"country", "asn"}
    assert all(dataset["release"] == "2026-04" for dataset in metadata["datasets"])
    assert len(requested_urls) == 2


def test_update_requires_release_and_out_of_band_sha256_before_network_access(tmp_path: Path) -> None:
    opened = False

    def opener(request, *, timeout):
        nonlocal opened
        del request, timeout
        opened = True
        raise AssertionError("network must not be reached")

    with pytest.raises(GeoIpUpdateError, match="pinned release"):
        update_dbip_lite(
            target_dir=tmp_path,
            expected_sha256={"country": "0" * 64, "asn": "1" * 64},
            opener=opener,
        )

    with pytest.raises(GeoIpUpdateError, match="SHA-256"):
        update_dbip_lite(target_dir=tmp_path, release="2026-04", opener=opener)

    assert opened is False


@pytest.mark.parametrize("invalid_value", [float("nan"), float("inf"), 0.0, -1.0])
def test_download_limits_reject_non_finite_and_non_positive_values(invalid_value: float) -> None:
    with pytest.raises(GeoIpUpdateError, match="finite and greater than zero"):
        GeoIpDownloadLimits(max_expansion_ratio=invalid_value)


@pytest.mark.parametrize("advertise_size", [True, False])
def test_update_rejects_compressed_archive_over_limit(
    tmp_path: Path,
    advertise_size: bool,
) -> None:
    archive = gzip.compress(_mmdb_payload("compressed-limit"), mtime=0) + b"padding" * 100
    advertised = len(archive) if advertise_size else 1

    with pytest.raises(GeoIpUpdateError, match="compressed"):
        update_dbip_lite(
            target_dir=tmp_path,
            release="2026-04",
            datasets=("country",),
            expected_sha256={"country": hashlib.sha256(archive).hexdigest()},
            limits=GeoIpDownloadLimits(max_compressed_bytes=len(archive) - 1),
            opener=lambda request, timeout: FakeResponse(
                archive,
                content_length=advertised,
            ),
            mmdb_validator=lambda path, dataset: None,
        )


def test_update_rejects_gzip_bomb_and_preserves_existing_database(tmp_path: Path) -> None:
    target = tmp_path / "dbip-country-lite.mmdb"
    target.write_bytes(b"previous-valid-mmdb")
    archive = gzip.compress(b"A" * 64_000, mtime=0)

    results = update_dbip_lite(
        target_dir=tmp_path,
        release="2026-04",
        datasets=("country",),
        expected_sha256={"country": hashlib.sha256(archive).hexdigest()},
        limits=GeoIpDownloadLimits(
            max_compressed_bytes=1_024,
            max_decompressed_bytes=128_000,
            max_expansion_ratio=10.0,
            total_deadline_seconds=30.0,
            max_directory_bytes=256_000,
        ),
        opener=lambda request, timeout: FakeResponse(archive),
        mmdb_validator=lambda path, dataset: None,
    )

    assert results == ()
    assert target.read_bytes() == b"previous-valid-mmdb"
    assert list(tmp_path.glob(".*.tmp")) == []


def test_update_enforces_total_deadline_during_response_reads(tmp_path: Path) -> None:
    clock = FakeClock()
    archive = gzip.compress(_mmdb_payload("slow"), mtime=0)

    with pytest.raises(GeoIpUpdateError, match="deadline"):
        update_dbip_lite(
            target_dir=tmp_path,
            release="2026-04",
            datasets=("country",),
            expected_sha256={"country": hashlib.sha256(archive).hexdigest()},
            limits=GeoIpDownloadLimits(total_deadline_seconds=1.0),
            opener=lambda request, timeout: FakeResponse(archive, clock=clock),
            monotonic=clock,
            mmdb_validator=lambda path, dataset: None,
        )

    assert list(tmp_path.glob(".*.tmp")) == []


def test_update_rejects_checksum_mismatch_and_invalid_mmdb(tmp_path: Path) -> None:
    archive = gzip.compress(_mmdb_payload("invalid"), mtime=0)

    with pytest.raises(GeoIpUpdateError, match="SHA-256 mismatch"):
        update_dbip_lite(
            target_dir=tmp_path,
            release="2026-04",
            datasets=("country",),
            expected_sha256={"country": "0" * 64},
            opener=lambda request, timeout: FakeResponse(archive),
            mmdb_validator=lambda path, dataset: None,
        )

    with pytest.raises(GeoIpUpdateError, match="valid MMDB"):
        update_dbip_lite(
            target_dir=tmp_path,
            release="2026-04",
            datasets=("country",),
            expected_sha256={"country": hashlib.sha256(archive).hexdigest()},
            opener=lambda request, timeout: FakeResponse(archive),
        )

    assert not (tmp_path / "dbip-country-lite.mmdb").exists()
    assert list(tmp_path.glob(".*.tmp")) == []


def test_update_enforces_directory_quota_before_replacing_database(tmp_path: Path) -> None:
    nested_dir = tmp_path / "nested"
    nested_dir.mkdir()
    (nested_dir / "unrelated.bin").write_bytes(b"x" * 2_000)
    archive = gzip.compress(_mmdb_payload("quota"), mtime=0)

    with pytest.raises(GeoIpUpdateError, match="directory quota"):
        update_dbip_lite(
            target_dir=tmp_path,
            release="2026-04",
            datasets=("country",),
            expected_sha256={"country": hashlib.sha256(archive).hexdigest()},
            limits=GeoIpDownloadLimits(max_directory_bytes=3_000),
            opener=lambda request, timeout: FakeResponse(archive),
            mmdb_validator=lambda path, dataset: None,
        )


def test_update_dbip_lite_optional_mode_does_not_block_without_downloads(tmp_path: Path) -> None:
    def opener(request, *, timeout):
        del timeout
        raise urllib.error.HTTPError(request.full_url, 404, "Not Found", hdrs=None, fp=None)

    results = update_dbip_lite(
        target_dir=tmp_path,
        release="2026-04",
        expected_sha256={"country": "0" * 64, "asn": "1" * 64},
        optional=True,
        opener=opener,
    )

    assert results == ()
    assert not (tmp_path / "metadata.json").exists()


def test_geoip_default_downloader_rejects_cross_target_redirects() -> None:
    handler = _RejectRedirectHandler()

    redirected = handler.redirect_request(
        None,
        None,
        302,
        "Found",
        {},
        "https://redirected.example.net/archive.mmdb.gz",
    )

    assert redirected is None


def test_geoip_cli_rejects_missing_egress_approval_even_in_optional_mode(
    monkeypatch,
    capsys,
) -> None:
    update_called = False

    def fake_update(**kwargs):
        nonlocal update_called
        del kwargs
        update_called = True
        return ()

    monkeypatch.setattr("honeypot.geoip_update.update_dbip_lite", fake_update)

    result = geoip_main(("--optional",))

    assert result == 1
    assert update_called is False
    assert "APPROVED_EGRESS_TARGETS" in capsys.readouterr().err


def test_geoip_cli_accepts_explicit_target_and_cidr_approval(monkeypatch) -> None:
    update_called = False

    def fake_update(**kwargs):
        nonlocal update_called
        del kwargs
        update_called = True
        return ()

    monkeypatch.setattr("honeypot.geoip_update.update_dbip_lite", fake_update)
    monkeypatch.setattr(
        "honeypot.geoip_update.resolve_host_addresses",
        lambda host, port: ("93.184.216.34",),
    )

    result = geoip_main(
        (
            "--approved-egress-targets",
            DBIP_EGRESS_TARGET_SPEC,
            "--approved-egress-cidrs",
            "93.184.216.0/24",
        )
    )

    assert result == 0
    assert update_called is True


@pytest.mark.parametrize(
    ("extra_args", "expected_error"),
    (
        ((), "APPROVED_EGRESS_CIDRS"),
        (
            (
                "--approved-egress-cidrs",
                "93.184.216.0/24",
                "--prohibited-ot-cidrs",
                "93.184.216.0/24",
            ),
            "PROHIBITED_OT_CIDRS",
        ),
    ),
)
def test_geoip_cli_rejects_missing_cidr_or_prohibited_network(
    monkeypatch,
    capsys,
    extra_args: tuple[str, ...],
    expected_error: str,
) -> None:
    update_called = False

    def fake_update(**kwargs):
        nonlocal update_called
        del kwargs
        update_called = True
        return ()

    monkeypatch.setattr("honeypot.geoip_update.update_dbip_lite", fake_update)
    monkeypatch.setattr(
        "honeypot.geoip_update.resolve_host_addresses",
        lambda host, port: ("93.184.216.34",),
    )

    result = geoip_main(
        (
            "--approved-egress-targets",
            DBIP_EGRESS_TARGET_SPEC,
            *extra_args,
        )
    )

    assert result == 1
    assert update_called is False
    assert expected_error in capsys.readouterr().err


def _checksums(archives: dict[str, bytes]) -> dict[str, str]:
    return {name: hashlib.sha256(payload).hexdigest() for name, payload in archives.items()}


def _mmdb_payload(seed: str) -> bytes:
    return (f"MMDB:{seed}\n".encode("ascii") * 256)[:4096]
