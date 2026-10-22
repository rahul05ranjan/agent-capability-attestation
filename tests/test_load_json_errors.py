"""Regression tests for ``_load_json`` input errors (issue #72).

A missing or unreadable attestation file escaped as an unhandled traceback
with exit 1 — the code a *failing attestation* uses — instead of the exit 2
the README documents for malformed input. ``_load_json`` now maps
``OSError`` (missing, permission denied, …) and ``UnicodeDecodeError``
(binary bytes) to the same `ERROR: cannot read …` + exit 2 path that
invalid JSON already used.
"""

from __future__ import annotations

import os

import pytest
from click.testing import CliRunner

from agent_capability_attestation.cli import cli


def _invoke(tmp_path, args):
    return CliRunner().invoke(cli, args)


def test_validate_missing_file_exits_two(tmp_path):
    result = _invoke(tmp_path, ["validate", str(tmp_path / "nope.json")])
    assert result.exit_code == 2, result.output
    assert "cannot read" in result.output
    assert "Traceback" not in result.output


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file permissions")
def test_validate_unreadable_file_exits_two(tmp_path):
    path = tmp_path / "locked.json"
    path.write_text("{}")
    path.chmod(0o000)
    try:
        result = _invoke(tmp_path, ["validate", str(path)])
        assert result.exit_code == 2, result.output
        assert "cannot read" in result.output
    finally:
        path.chmod(0o644)


def test_validate_binary_file_exits_two(tmp_path):
    path = tmp_path / "attestation.bin"
    path.write_bytes(b"\xff\xfe\x00garbage-not-utf8")
    result = _invoke(tmp_path, ["validate", str(path)])
    assert result.exit_code == 2, result.output
    assert "cannot read" in result.output


def test_check_chain_missing_file_exits_two(tmp_path):
    result = _invoke(tmp_path, ["check-chain", str(tmp_path / "nope.json")])
    assert result.exit_code == 2, result.output
    assert "cannot read" in result.output


def test_valid_json_still_loads(tmp_path):
    path = tmp_path / "ok.json"
    path.write_text("{}")
    # A bare {} is a JSON *value* but not a valid attestation: it must be
    # reported as the documented malformed-payload error (exit 2), not as a
    # read failure — proving the read itself succeeded.
    result = _invoke(tmp_path, ["validate", str(path)])
    assert result.exit_code == 2, result.output
    assert "cannot read" not in result.output
