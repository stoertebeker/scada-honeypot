"""DB-IP Lite GeoIP database updater.

The updater intentionally supports only fixed DB-IP Lite download URLs. It is
not a generic URL fetcher, so deployments do not gain a configurable egress or
SSRF primitive.
"""

from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import gzip
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile
from typing import Any
import urllib.error
import urllib.request

DBIP_PROVIDER_NAME = "DB-IP Lite"
DBIP_ATTRIBUTION_LABEL = "IP Geolocation by DB-IP"
DBIP_ATTRIBUTION_URL = "https://db-ip.com"
DBIP_LICENSE_NAME = "Creative Commons Attribution 4.0 International (CC BY 4.0)"
DBIP_LICENSE_URL = "https://creativecommons.org/licenses/by/4.0/"
DBIP_DOWNLOAD_BASE_URL = "https://download.db-ip.com/free"
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


class GeoIpUpdateError(RuntimeError):
    """Raised when a GeoIP update cannot be completed."""


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
    last_modified: str


def update_dbip_lite(
    *,
    target_dir: Path = DEFAULT_TARGET_DIR,
    release: str | None = None,
    datasets: Sequence[str] = DEFAULT_DATASETS,
    timeout_seconds: float = 60.0,
    optional: bool = False,
    now: datetime | None = None,
    opener: Callable[..., Any] | None = None,
) -> tuple[GeoIpDatasetResult, ...]:
    """Download DB-IP Lite Country/ASN MMDBs and write attribution metadata."""

    normalized_now = _normalized_now(now)
    target_dir = target_dir.expanduser()
    target_dir.mkdir(parents=True, exist_ok=True)
    release_candidates = _release_candidates(release=release, now=normalized_now)
    normalized_datasets = _normalize_datasets(datasets)
    open_url = urllib.request.urlopen if opener is None else opener

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
) -> GeoIpDatasetResult:
    request = urllib.request.Request(download_url, headers={"User-Agent": _USER_AGENT})
    digest = hashlib.sha256()
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
        with opener(request, timeout=timeout_seconds) as response:
            last_modified = str(getattr(response, "headers", {}).get("Last-Modified", ""))
            with gzip.GzipFile(fileobj=response) as compressed, temp_path.open("wb") as output:
                while chunk := compressed.read(1024 * 1024):
                    output.write(chunk)
                    digest.update(chunk)
                    bytes_written += len(chunk)
        if bytes_written < 1024:
            raise GeoIpUpdateError(f"{dataset} MMDB from {download_url} is unexpectedly small")
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
        sha256=digest.hexdigest(),
        last_modified=last_modified,
    )


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


def _normalized_now(now: datetime | None) -> datetime:
    value = datetime.now(UTC) if now is None else now
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _format_dt(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Download DB-IP Lite Country and ASN MMDBs.")
    parser.add_argument("--provider", choices=("dbip-lite",), default="dbip-lite")
    parser.add_argument("--target-dir", type=Path, default=DEFAULT_TARGET_DIR)
    parser.add_argument("--release", help="DB-IP release month in YYYY-MM format; defaults to current/previous month")
    parser.add_argument(
        "--dataset",
        action="append",
        choices=DEFAULT_DATASETS,
        help="Dataset to update; can be passed multiple times. Defaults to country and asn.",
    )
    parser.add_argument("--timeout-seconds", type=float, default=60.0)
    parser.add_argument(
        "--optional",
        action="store_true",
        help="Log download errors and exit 0 so honeypot startup is not blocked by DB-IP availability.",
    )
    args = parser.parse_args(argv)

    try:
        results = update_dbip_lite(
            target_dir=args.target_dir,
            release=args.release,
            datasets=tuple(args.dataset or DEFAULT_DATASETS),
            timeout_seconds=args.timeout_seconds,
            optional=args.optional,
        )
    except GeoIpUpdateError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for result in results:
        print(f"{result.name}: {result.status} {result.target_path} from {result.download_url}")
    if results:
        print(f"attribution: {DBIP_ATTRIBUTION_LABEL} ({DBIP_ATTRIBUTION_URL}), {DBIP_LICENSE_NAME}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
