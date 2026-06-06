import re
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent
RUNTIME_SKILL_DIR = PROJECT_ROOT / "skills" / "agent_runtime"
SAFE_SKILL_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


def _failure(skill_name: str, error: str) -> dict[str, Any]:
    """Return the standard safe failure shape for skill loading."""
    return {
        "loaded": False,
        "skill_name": skill_name,
        "path": None,
        "content": "",
        "error": error,
    }


def _display_path(path: Path) -> str:
    """Return a stable path string without affecting loader security checks."""
    try:
        return path.relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return str(path)


def _is_safe_skill_name(skill_name: str) -> bool:
    """
    Validate that a skill name is a single local runtime skill directory name.

    This helper does not execute skill content, tools, workflows, or requests.
    It only rejects names that could escape the runtime skill directory.

    Path traversal protection is intentionally strict: runtime skills live at
    skills/agent_runtime/<skill_name>/SKILL.md, so slashes, backslashes,
    absolute paths, drive-qualified paths, and parent-directory markers are not
    valid skill names.
    """
    if not isinstance(skill_name, str) or not skill_name:
        return False

    if Path(skill_name).is_absolute():
        return False

    if "/" in skill_name or "\\" in skill_name:
        return False

    if ".." in skill_name:
        return False

    return SAFE_SKILL_NAME_PATTERN.fullmatch(skill_name) is not None


def load_runtime_skill(skill_name: str) -> dict[str, Any]:
    """
    Load a runtime skill Markdown file as plain text.

    The loader reads only:
    skills/agent_runtime/<skill_name>/SKILL.md

    It does not execute the Markdown content, execute MCP tools, call
    workflows, send HTTP or other external requests, modify findings, write
    logs, update config, or touch target state. The returned content is text
    for a future planner or runtime agent to inspect.

    Safety boundary: skill_name is validated before path construction, the
    resolved SKILL.md path must remain under skills/agent_runtime, and failures
    return loaded=false instead of raising to callers.
    """
    if not _is_safe_skill_name(skill_name):
        return _failure(skill_name, "Unsafe skill name.")

    try:
        base_dir = RUNTIME_SKILL_DIR.resolve()
        skill_path = (base_dir / skill_name / "SKILL.md").resolve()
    except OSError as error:
        return _failure(skill_name, f"Failed to resolve skill path: {error}")

    # Defense in depth: validation rejects separators, but resolved-path
    # containment prevents future changes from accidentally allowing escape.
    if base_dir not in skill_path.parents:
        return _failure(skill_name, "Resolved skill path escapes runtime skill directory.")

    if not skill_path.is_file():
        return _failure(skill_name, "Skill not found.")

    try:
        content = skill_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        return _failure(skill_name, f"Failed to read skill file: {error}")

    return {
        "loaded": True,
        "skill_name": skill_name,
        "path": _display_path(skill_path),
        "content": content,
    }
