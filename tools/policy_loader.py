import json
from pathlib import Path
from typing import Any
from json import JSONDecodeError


CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
TOOL_RISK_PROFILES_PATH = CONFIG_DIR / "tool_risk_profiles.json"


def load_json_config(path: str | Path) -> dict[str, Any]:
    """
    Load a JSON config file and return its parsed top-level object.

    This helper only reads a local config file. It does not execute MCP tools,
    call workflows, send external requests, or modify runtime state.

    Safety boundary: config loading fails closed. Missing files, malformed JSON,
    unreadable files, and non-object top-level values return an empty dict so a
    bad policy file cannot crash the MCP server or accidentally allow an unknown
    policy state.
    """
    config_path = Path(path)

    try:
        with config_path.open("r", encoding="utf-8") as config_file:
            data = json.load(config_file)
    except (FileNotFoundError, JSONDecodeError, OSError):
        # Fail closed: callers must treat an empty policy as no tools allowed.
        return {}

    if not isinstance(data, dict):
        # Fail closed: the policy contract requires an object keyed by tool name.
        return {}

    return data


def load_tool_risk_profiles(
    path: str | Path = TOOL_RISK_PROFILES_PATH,
) -> dict[str, Any]:
    """
    Load tool risk profiles from JSON config.

    This helper only reads the configured local JSON file. It does not execute
    any tool, call a workflow, send an external request, or modify state.

    Safety boundary: failures are delegated to load_json_config, which returns
    an empty dict for missing, malformed, or structurally invalid config.
    """
    return load_json_config(path)
