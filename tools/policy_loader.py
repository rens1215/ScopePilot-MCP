import json
from pathlib import Path
from typing import Any
from json import JSONDecodeError


CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
TOOL_RISK_PROFILES_PATH = CONFIG_DIR / "tool_risk_profiles.json"


def load_json_config(path: str | Path) -> dict[str, Any]:
    """
    Load a JSON config file and return its parsed object.

    Config loading fails closed so a bad policy file cannot crash the MCP
    server or accidentally allow an unknown policy state.
    """
    config_path = Path(path)

    try:
        with config_path.open("r", encoding="utf-8") as config_file:
            data = json.load(config_file)
    except (FileNotFoundError, JSONDecodeError, OSError):
        return {}

    if not isinstance(data, dict):
        return {}

    return data


def load_tool_risk_profiles(
    path: str | Path = TOOL_RISK_PROFILES_PATH,
) -> dict[str, Any]:
    """
    Load tool risk profiles from JSON config.
    """
    return load_json_config(path)
