from pathlib import Path

import pytest

from honeypot.runtime_reset import reset_local_runtime_artifacts


def test_reset_runtime_artifacts_rejects_directory_paths(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    event_store_dir = tmp_path / "events"
    event_store_dir.mkdir()
    env_file.write_text(
        "\n".join(
            (
                "SITE_CODE=runtime-reset-guard",
                f"EVENT_STORE_PATH={event_store_dir}",
            )
        )
        + "\n",
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="Verzeichnis-Artefaktpfad"):
        reset_local_runtime_artifacts(env_file=str(env_file))
