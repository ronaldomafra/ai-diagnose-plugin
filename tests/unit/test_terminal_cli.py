from __future__ import annotations

from argparse import Namespace
from pathlib import Path

from diagnose.terminal.server import _doctor


def test_doctor_is_read_only_for_a_fresh_configuration_directory(tmp_path: Path) -> None:
    config_dir = tmp_path / "missing-config"
    endpoint = tmp_path / "missing-endpoint"

    exit_code = _doctor(Namespace(config_dir=str(config_dir), endpoint=str(endpoint)))

    assert exit_code == 0
    assert not config_dir.exists()
    assert not endpoint.exists()
