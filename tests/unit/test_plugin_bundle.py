from __future__ import annotations

import json
import tomllib
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
PLUGIN_ROOT = PROJECT_ROOT / "plugins" / "diagnose-plugin"


def test_plugin_bundle_matches_the_m0_contract() -> None:
    manifest = json.loads(
        (PLUGIN_ROOT / ".codex-plugin" / "plugin.json").read_text(encoding="utf-8")
    )
    mcp_configuration = json.loads((PLUGIN_ROOT / ".mcp.json").read_text(encoding="utf-8"))

    assert manifest["name"] == PLUGIN_ROOT.name == "diagnose-plugin"
    assert manifest["version"] == "0.1.0"
    assert manifest["skills"] == "./skills/"
    assert manifest["mcpServers"] == "./.mcp.json"
    assert mcp_configuration == {"diagnose": {"command": "diagnose-mcp", "args": []}}
    assert "mcpServers" not in mcp_configuration

    serialized = json.dumps(manifest) + json.dumps(mcp_configuration)
    assert "[TODO:" not in serialized


def test_skill_is_explicit_only_and_depends_on_the_diagnose_mcp_server() -> None:
    skill = (PLUGIN_ROOT / "skills" / "diagnose" / "SKILL.md").read_text(encoding="utf-8")
    openai = yaml.safe_load(
        (PLUGIN_ROOT / "skills" / "diagnose" / "agents" / "openai.yaml").read_text(encoding="utf-8")
    )

    assert skill.startswith("---\n")
    assert "name: diagnose" in skill.split("---", 2)[1]
    assert openai["policy"]["allow_implicit_invocation"] is False
    assert openai["dependencies"]["tools"] == [
        {
            "type": "mcp",
            "value": "diagnose",
            "description": "Human-approved diagnostic tools",
            "transport": "stdio",
        }
    ]


def test_distribution_declares_both_console_scripts_and_packaged_launchers() -> None:
    project = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert project["project"]["scripts"] == {
        "diagnose-mcp": "diagnose.mcp.server:main",
        "diagnose-terminal": "diagnose.terminal.server:main",
    }
    assert (
        (PLUGIN_ROOT / "scripts" / "diagnose-mcp")
        .read_text(encoding="utf-8")
        .startswith("#!/bin/sh\n")
    )
    assert (
        (PLUGIN_ROOT / "scripts" / "diagnose-mcp.cmd")
        .read_text(encoding="utf-8")
        .startswith("@echo off\n")
    )
