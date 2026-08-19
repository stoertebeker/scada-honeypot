"""DB-IP Lite GeoIP database updater.

The updater intentionally supports only fixed DB-IP Lite download URLs. It is
not a generic URL fetcher, so deployments do not gain a configurable egress or
SSRF primitive.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import gzip
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
import time
from typing import Any
import urllib.error
from urllib.parse import urlsplit
import urllib.request

import maxminddb

from honeypot.runtime_egress import EgressTarget, resolve_approved_egress_targets, resolve_host_addresses

DBIP_PROVIDER_NAME = "DB-IP Lite"
DBIP_ATTRIBUTION_LABEL = "IP Geolocation by DB-IP"
DBIP_ATTRIBUTION_URL = "https://db-ip.com"
DBIP_LICENSE_NAME = "Creative Commons Attribution 4.0 International (CC BY 4.0)"
DBIP_LICENSE_URL = "https://creativecommons.org/licenses/by/4.0/"
DBIP_DOWNLOAD_BASE_URL = "https://download.db-ip.com/free"
_DBIP_DOWNLOAD_URL = urlsplit(DBIP_DOWNLOAD_BASE_URL)
_DBIP_EGRESS_TARGET = EgressTarget(
    target_type="geoip-dbip",
    host=str(_DBIP_DOWNLOAD_URL.hostname),
    port=443 if _DBIP_DOWNLOAD_URL.port is None else _DBIP_DOWNLOAD_URL.port,
)
DBIP_EGRESS_TARGET_SPEC = _DBIP_EGRESS_TARGET.spec
DBIP_SOURCE_PAGES = {
    "country": "https://db-ip.com/db/download/ip-to-country-lite",
    "asn": "https://db-ip.com/db/download/ip-to-asn-lite",
}
DEFAULT_TARGET_DIR = Path("data/geoip")
DEFAULT_DATASETS = ("country", "asn")
METADATA_FILENAME = "metadata.json"
_RELEASE_PATTERN = re.compile(r"^\d{4}-\d{2}$")
_DATASET_FILENAMES = {
    "country": ("dbip-country-lite-{release}.mmdb.gz", "dbip-country-lite.mmdb"),
    "asn": ("dbip-asn-lite-{release}.mmdb.gz", "dbip-asn-lite.mmdb"),
}
_USER_AGENT = "scada-honeypot-geoip-updater/1"
_SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")
_READ_CHUNK_BYTES = 64 * 1024


class GeoIpUpdateError(RuntimeError):
    """Raised when a GeoIP update cannot be completed."""


class _RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        del req, fp, code, msg, headers, newurl
        return None


@dataclass(frozen=True, slots=True)
class GeoIpDownloadLimits:
    """Hard resource ceilings for one complete updater run."""

    max_compressed_bytes: int = 32 * 1024 * 1024
    max_decompressed_bytes: int = 128 * 1024 * 1024
    max_expansion_ratio: float = 64.0
    total_deadline_seconds: float = 120.0
    max_directory_bytes: int = 256 * 1024 * 1024

    def __post_init__(self) -> None:
        values = {
            "max_compressed_bytes": self.max_compressed_bytes,
            "max_decompressed_bytes": self.max_decompressed_bytes,
            "max_expansion_ratio": self.max_expansion_ratio,
            "total_deadline_seconds": self.total_deadline_seconds,
            "max_directory_bytes": self.max_directory_bytes,
        }
        for name, value in values.items():
            if not math.isfinite(value) or value <= 0:
                raise GeoIpUpdateError(f"{name} must be finite and greater than zero")


class _BoundedDeadlineReader:
    def __init__(
        self,
        raw: Any,
        *,
        max_bytes: int,
        deadline: float,
        monotonic: Callable[[], float],
        dataset: str,
    ) -> None:
        self._raw = raw
        self._max_bytes = max_bytes
        self._deadline = deadline
        self._monotonic = monotonic
        self._dataset = dataset
        self.bytes_read = 0
        self.digest = hashlib.sha256()

    def read(self, size: int = -1) -> bytes:
        self.check_deadline()
        chunk = self._raw.read(size)
        self.check_deadline()
        self.bytes_read += len(chunk)
        if self.bytes_read > self._max_bytes:
            raise GeoIpUpdateError(
                f"{self._dataset} compressed download exceeds "
                f"{self._max_bytes} byte limit"
            )
        self.digest.update(chunk)
        return chunk

    def check_deadline(self) -> None:
        if self._monotonic() > self._deadline:
            raise GeoIpUpdateError(f"{self._dataset} update exceeded total deadline")


@dataclass(frozen=True, slots=True)
class GeoIpDatasetResult:
    name: str
    release: str
    status: str
    source_page: str
    download_url: str
    target_path: str
    bytes_written: int
    sha256: str
    source_sha256: str
    last_modified: str


def update_dbip_lite(
    *,
    target_dir: Path = DEFAULT_TARGET_DIR,
    release: str | None = None,
    datasets: Sequence[str] = DEFAULT_DATASETS,
    timeout_seconds: float = 60.0,
    expected_sha256: Mapping[str, str] | None = None,
    limits: GeoIpDownloadLimits | None = None,
    optional: bool = False,
    now: datetime | None = None,
    opener: Callable[..., Any] | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    mmdb_validator: Callable[[Path, str], None] | None = None,
) -> tuple[GeoIpDatasetResult, ...]:
    """Download authenticated DB-IP Lite MMDBs within hard resource bounds."""

    normalized_now = _normalized_now(now)
    normalized_datasets = _normalize_datasets(datasets)
    normalized_checksums = _normalize_expected_sha256(
        release=release,
        datasets=normalized_datasets,
        expected_sha256=expected_sha256,
    )
    download_limits = GeoIpDownloadLimits() if limits is None else limits
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise GeoIpUpdateError("timeout_seconds must be finite and greater than zero")
    target_dir = target_dir.expanduser()
    target_dir.mkdir(parents=True, exist_ok=True)
    release_candidates = _release_candidates(release=release, now=normalized_now)
    open_url = _open_dbip_url if opener is None else opener
    validate_mmdb = _validate_mmdb if mmdb_validator is None else mmdb_validator
    deadline = monotonic() + download_limits.total_deadline_seconds

    results: list[GeoIpDatasetResult] = []
    for dataset in normalized_datasets:
        try:
            results.append(
                _update_dataset(
                    dataset=dataset,
                    releases=release_candidates,
                    target_dir=target_dir,
                    timeout_seconds=timeout_seconds,
                    opener=open_url,
                    expected_sha256=normalized_checksums[dataset],
                    limits=download_limits,
                    deadline=deadline,
                    monotonic=monotonic,
                    mmdb_validator=validate_mmdb,
                )
            )
        except GeoIpUpdateError as exc:
            target_path = target_dir / _DATASET_FILENAMES[dataset][1]
            if optional:
                print(f"warning: {exc}", file=sys.stderr)
                continue
            if target_path.is_file():
                print(f"warning: {exc}; keeping existing {target_path}", file=sys.stderr)
                continue
            raise

    if results:
        _write_metadata(target_dir=target_dir, results=tuple(results), now=normalized_now)
    return tuple(results)


def _update_dataset(
    *,
    dataset: str,
    releases: tuple[str, ...],
    target_dir: Path,
    timeout_seconds: float,
    opener: Callable[..., Any],
    expected_sha256: str,
    limits: GeoIpDownloadLimits,
    deadline: float,
    monotonic: Callable[[], float],
    mmdb_validator: Callable[[Path, str], None],
) -> GeoIpDatasetResult:
    errors: list[str] = []
    for release in releases:
        compressed_name, stable_name = _DATASET_FILENAMES[dataset]
        download_url = f"{DBIP_DOWNLOAD_BASE_URL}/{compressed_name.format(release=release)}"
        target_path = target_dir / stable_name
        try:
            return _download_gzip_mmdb(
                dataset=dataset,
                release=release,
                download_url=download_url,
                target_path=target_path,
                timeout_seconds=timeout_seconds,
                opener=opener,
                expected_sha256=expected_sha256,
                limits=limits,
                deadline=deadline,
                monotonic=monotonic,
                mmdb_validator=mmdb_validator,
            )
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                errors.append(f"{download_url}: HTTP 404")
                continue
            raise GeoIpUpdateError(f"{dataset} download failed from {download_url}: HTTP {exc.code}") from exc
        except (OSError, gzip.BadGzipFile, EOFError) as exc:
            raise GeoIpUpdateError(f"{dataset} download failed from {download_url}: {exc}") from exc
    joined_errors = "; ".join(errors) if errors else "no release candidates"
    raise GeoIpUpdateError(f"{dataset} MMDB not available from DB-IP Lite ({joined_errors})")


def _download_gzip_mmdb(
    *,
    dataset: str,
    release: str,
    download_url: str,
    target_path: Path,
    timeout_seconds: float,
    opener: Callable[..., Any],
    expected_sha256: str,
    limits: GeoIpDownloadLimits,
    deadline: float,
    monotonic: Callable[[], float],
    mmdb_validator: Callable[[Path, str], None],
) -> GeoIpDatasetResult:
    request = urllib.request.Request(download_url, headers={"User-Agent": _USER_AGENT})
    decompressed_digest = hashlib.sha256()
    bytes_written = 0
    target_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        prefix=f".{target_path.name}.",
        suffix=".tmp",
        dir=target_path.parent,
        delete=False,
    ) as temp_file:
        temp_path = Path(temp_file.name)
    try:
        existing_directory_bytes = _directory_size_excluding(
            target_path.parent,
            excluded={temp_path},
        )
        if existing_directory_bytes > limits.max_directory_bytes:
            raise GeoIpUpdateError(
                f"{dataset} target already exceeds {limits.max_directory_bytes} byte directory quota"
            )
        remaining_seconds = deadline - monotonic()
        if remaining_seconds <= 0:
            raise GeoIpUpdateError(f"{dataset} update exceeded total deadline")
        request_timeout = min(timeout_seconds, remaining_seconds)
        with opener(request, timeout=request_timeout) as response:
            headers = getattr(response, "headers", {})
            _reject_oversized_content_length(
                dataset=dataset,
                content_length=headers.get("Content-Length"),
                max_compressed_bytes=limits.max_compressed_bytes,
            )
            last_modified = str(getattr(response, "headers", {}).get("Last-Modified", ""))
            bounded_response = _BoundedDeadlineReader(
                response,
                max_bytes=limits.max_compressed_bytes,
                deadline=deadline,
                monotonic=monotonic,
                dataset=dataset,
            )
            with gzip.GzipFile(fileobj=bounded_response) as compressed, temp_path.open("wb") as output:
                while chunk := compressed.read(_READ_CHUNK_BYTES):
                    bounded_response.check_deadline()
                    bytes_written += len(chunk)
                    if bytes_written > limits.max_decompressed_bytes:
                        raise GeoIpUpdateError(
                            f"{dataset} decompressed MMDB exceeds "
                            f"{limits.max_decompressed_bytes} byte limit"
                        )
                    if existing_directory_bytes + bytes_written > limits.max_directory_bytes:
                        raise GeoIpUpdateError(
                            f"{dataset} update would exceed "
                            f"{limits.max_directory_bytes} byte directory quota"
                        )
                    if bytes_written > bounded_response.bytes_read * limits.max_expansion_ratio:
                        raise GeoIpUpdateError(
                            f"{dataset} gzip expansion ratio exceeds "
                            f"{limits.max_expansion_ratio:g}:1 limit"
                        )
                    output.write(chunk)
                    decompressed_digest.update(chunk)
        if bytes_written < 1024:
            raise GeoIpUpdateError(f"{dataset} MMDB from {download_url} is unexpectedly small")
        source_sha256 = bounded_response.digest.hexdigest()
        if not hmac.compare_digest(source_sha256, expected_sha256):
            raise GeoIpUpdateError(
                f"{dataset} SHA-256 mismatch for authenticated archive from {download_url}"
            )
        mmdb_validator(temp_path, dataset)
        temp_path.replace(target_path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


    return GeoIpDatasetResult(
        name=dataset,
        release=release,
        status="updated",
        source_page=DBIP_SOURCE_PAGES[dataset],
        download_url=download_url,
        target_path=str(target_path),
        bytes_written=bytes_written,
        sha256=decompressed_digest.hexdigest(),
        source_sha256=source_sha256,
        last_modified=last_modified,
    )


def _open_dbip_url(request: urllib.request.Request, *, timeout: float):
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _RejectRedirectHandler(),
    )
    return opener.open(request, timeout=timeout)


def _reject_oversized_content_length(
    *, dataset: str, content_length: Any, max_compressed_bytes: int
) -> None:
    try:
        advertised_bytes = int(content_length)
    except (TypeError, ValueError):
        return
    if advertised_bytes > max_compressed_bytes:
        raise GeoIpUpdateError(
            f"{dataset} advertised compressed size exceeds {max_compressed_bytes} byte limit"
        )


def _validate_mmdb(path: Path, dataset: str) -> None:
    try:
        with maxminddb.open_database(path) as reader:
            metadata = reader.metadata()
            if metadata.node_count <= 0 or not metadata.database_type:
                raise ValueError("missing MMDB metadata")
    except Exception as exc:
        raise GeoIpUpdateError(f"{dataset} download is not a valid MMDB database") from exc


def _directory_size_excluding(directory: Path, *, excluded: set[Path]) -> int:
    excluded_paths = {path.absolute() for path in excluded}
    total = 0
    for root, directory_names, file_names in os.walk(directory, followlinks=False):
        root_path = Path(root)
        directory_names[:] = [
            name for name in directory_names if not (root_path / name).is_symlink()
        ]
        for name in file_names:
            path = root_path / name
            if path.absolute() in excluded_paths:
                continue
            try:
                file_stat = path.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISREG(file_stat.st_mode):
                total += file_stat.st_size
    return total


def _write_metadata(*, target_dir: Path, results: tuple[GeoIpDatasetResult, ...], now: datetime) -> None:
    metadata = {
        "provider": DBIP_PROVIDER_NAME,
        "license": DBIP_LICENSE_NAME,
        "license_url": DBIP_LICENSE_URL,
        "attribution": {
            "label": DBIP_ATTRIBUTION_LABEL,
            "url": DBIP_ATTRIBUTION_URL,
        },
        "downloaded_at": _format_dt(now),
        "datasets": [asdict(result) for result in results],
    }
    metadata_path = target_dir / METADATA_FILENAME
    temp_path = metadata_path.with_name(f".{metadata_path.name}.tmp")
    temp_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temp_path.replace(metadata_path)


def _release_candidates(*, release: str | None, now: datetime) -> tuple[str, ...]:
    if release is not None:
        normalized_release = release.strip()
        _validate_release(normalized_release)
        return (normalized_release,)
    current_release = f"{now.year:04d}-{now.month:02d}"
    previous_year = now.year if now.month > 1 else now.year - 1
    previous_month = now.month - 1 if now.month > 1 else 12
    previous_release = f"{previous_year:04d}-{previous_month:02d}"
    return tuple(dict.fromkeys((current_release, previous_release)))


def _validate_release(release: str) -> None:
    if not _RELEASE_PATTERN.fullmatch(release):
        raise GeoIpUpdateError("release must use YYYY-MM format")
    month = int(release.split("-", 1)[1])
    if month < 1 or month > 12:
        raise GeoIpUpdateError("release month must be between 01 and 12")


def _normalize_datasets(datasets: Sequence[str]) -> tuple[str, ...]:
    normalized: list[str] = []
    for dataset in datasets:
        cleaned = dataset.strip().lower()
        if cleaned not in _DATASET_FILENAMES:
            raise GeoIpUpdateError(f"unsupported DB-IP Lite dataset: {dataset}")
        if cleaned not in normalized:
            normalized.append(cleaned)
    if not normalized:
        raise GeoIpUpdateError("at least one dataset is required")
    return tuple(normalized)


def _normalize_expected_sha256(
    *,
    release: str | None,
    datasets: tuple[str, ...],
    expected_sha256: Mapping[str, str] | None,
) -> dict[str, str]:
    if release is None or not release.strip():
        raise GeoIpUpdateError("a pinned release is required for authenticated GeoIP updates")
    checksums = {} if expected_sha256 is None else expected_sha256
    normalized: dict[str, str] = {}
    for dataset in datasets:
        checksum = str(checksums.get(dataset, "")).strip().lower()
        if not _SHA256_PATTERN.fullmatch(checksum):
            raise GeoIpUpdateError(f"an out-of-band SHA-256 is required for {dataset}")
        normalized[dataset] = checksum
    return normalized


def _normalized_now(now: datetime | None) -> datetime:
    value = datetime.now(UTC) if now is None else now
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _format_dt(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _split_csv_setting(raw_value: str) -> tuple[str, ...]:
    return tuple(item.strip().lower() for item in raw_value.split(",") if item.strip())


def _enforce_dbip_egress_policy(
    *,
    approved_targets: str,
    approved_cidrs: str,
    prohibited_cidrs: str,
) -> None:
    try:
        resolve_approved_egress_targets(
            targets=(_DBIP_EGRESS_TARGET,),
            approved_target_specs=_split_csv_setting(approved_targets),
            approved_cidrs=_split_csv_setting(approved_cidrs),
            prohibited_cidrs=_split_csv_setting(prohibited_cidrs),
            resolver=resolve_host_addresses,
        )
    except (RuntimeError, ValueError) as exc:
        raise GeoIpUpdateError(str(exc)) from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Download DB-IP Lite Country and ASN MMDBs.")
    parser.add_argument("--provider", choices=("dbip-lite",), default="dbip-lite")
    parser.add_argument("--target-dir", type=Path, default=DEFAULT_TARGET_DIR)
    parser.add_argument("--release", help="Required DB-IP release month pin in YYYY-MM format")
    parser.add_argument(
        "--dataset",
        action="append",
        choices=DEFAULT_DATASETS,
        help="Dataset to update; can be passed multiple times. Defaults to country and asn.",
    )
    parser.add_argument("--timeout-seconds", type=float, default=60.0)
    parser.add_argument("--country-sha256", help="Out-of-band SHA-256 for the pinned Country archive")
    parser.add_argument("--asn-sha256", help="Out-of-band SHA-256 for the pinned ASN archive")
    parser.add_argument("--max-compressed-bytes", type=int, default=32 * 1024 * 1024)
    parser.add_argument("--max-decompressed-bytes", type=int, default=128 * 1024 * 1024)
    parser.add_argument("--max-expansion-ratio", type=float, default=64.0)
    parser.add_argument("--total-deadline-seconds", type=float, default=120.0)
    parser.add_argument("--max-directory-bytes", type=int, default=256 * 1024 * 1024)
    parser.add_argument("--approved-egress-targets", default="")
    parser.add_argument("--approved-egress-cidrs", default="")
    parser.add_argument("--prohibited-ot-cidrs", default="")
    parser.add_argument(
        "--optional",
        action="store_true",
        help="Log download errors and exit 0 so honeypot startup is not blocked by DB-IP availability.",
    )
    args = parser.parse_args(argv)

    try:
        _enforce_dbip_egress_policy(
            approved_targets=args.approved_egress_targets,
            approved_cidrs=args.approved_egress_cidrs,
            prohibited_cidrs=args.prohibited_ot_cidrs,
        )
        results = update_dbip_lite(
            target_dir=args.target_dir,
            release=args.release,
            datasets=tuple(args.dataset or DEFAULT_DATASETS),
            timeout_seconds=args.timeout_seconds,
            expected_sha256={
                "country": args.country_sha256 or "",
                "asn": args.asn_sha256 or "",
            },
            limits=GeoIpDownloadLimits(
                max_compressed_bytes=args.max_compressed_bytes,
                max_decompressed_bytes=args.max_decompressed_bytes,
                max_expansion_ratio=args.max_expansion_ratio,
                total_deadline_seconds=args.total_deadline_seconds,
                max_directory_bytes=args.max_directory_bytes,
            ),
            optional=args.optional,
        )
    except GeoIpUpdateError as exc:
        if args.optional:
            print(f"warning: {exc}", file=sys.stderr)
            return 0
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for result in results:
        print(f"{result.name}: {result.status} {result.target_path} from {result.download_url}")
    if results:
        print(f"attribution: {DBIP_ATTRIBUTION_LABEL} ({DBIP_ATTRIBUTION_URL}), {DBIP_LICENSE_NAME}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
