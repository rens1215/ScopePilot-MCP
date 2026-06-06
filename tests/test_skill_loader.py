import sys
import tempfile
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tools import skill_loader
from tools.skill_loader import load_runtime_skill


def assert_true(condition, message):
    """
    Assert skill-loader test conditions without external dependencies.

    This helper does not execute tools, call workflows, send network requests,
    or modify application state. It raises only when a loader safety guarantee
    is not preserved.
    """
    if not condition:
        raise AssertionError(message)


def with_temp_skill_dir(test_func):
    """
    Run a test with a temporary runtime skill directory.

    The production loader normally reads skills/agent_runtime. Tests patch only
    the in-memory base directory so they can verify loader behavior without
    modifying the repository skills directory.
    """
    original_dir = skill_loader.RUNTIME_SKILL_DIR
    with tempfile.TemporaryDirectory() as temp_dir:
        skill_loader.RUNTIME_SKILL_DIR = Path(temp_dir)
        try:
            test_func(Path(temp_dir))
        finally:
            skill_loader.RUNTIME_SKILL_DIR = original_dir


def create_skill(base_dir, name, content):
    """Create a local test-only SKILL.md file under the temporary skill root."""
    skill_dir = base_dir / name
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(content, encoding="utf-8")


def test_load_existing_skill():
    """Protects successful local Markdown loading for an existing runtime skill."""
    def run(base_dir):
        create_skill(base_dir, "passive_recon", "# Passive Recon\n\nLocal guidance.")

        result = load_runtime_skill("passive_recon")

        assert_true(result["loaded"] is True, "Existing skill should load")
        assert_true(result["skill_name"] == "passive_recon", "Skill name should be preserved")
        assert_true(result["path"].endswith("passive_recon/SKILL.md") or result["path"].endswith("passive_recon\\SKILL.md"), "Path should identify SKILL.md")
        assert_true("Local guidance." in result["content"], "Content should contain Markdown text")

    with_temp_skill_dir(run)


def test_missing_skill_returns_loaded_false():
    """Protects safe failure when a runtime skill directory does not exist."""
    def run(_base_dir):
        result = load_runtime_skill("missing_skill")

        assert_true(result["loaded"] is False, "Missing skill should not load")
        assert_true(result["path"] is None, "Missing skill should return null path")
        assert_true(result["content"] == "", "Missing skill should return empty content")
        assert_true("error" in result, "Missing skill should include error")

    with_temp_skill_dir(run)


def test_path_traversal_rejected():
    """Protects against parent-directory traversal such as ../."""
    def run(_base_dir):
        result = load_runtime_skill("../passive_recon")

        assert_true(result["loaded"] is False, "Traversal skill name should be rejected")
        assert_true(result["path"] is None, "Rejected traversal should not expose path")
        assert_true(result["content"] == "", "Rejected traversal should return no content")

    with_temp_skill_dir(run)


def test_absolute_path_rejected():
    """Protects against absolute paths being treated as skill names."""
    def run(base_dir):
        absolute_name = str(base_dir / "passive_recon")

        result = load_runtime_skill(absolute_name)

        assert_true(result["loaded"] is False, "Absolute path should be rejected")
        assert_true(result["path"] is None, "Rejected absolute path should not expose path")
        assert_true(result["content"] == "", "Rejected absolute path should return no content")

    with_temp_skill_dir(run)


def test_backslash_and_nested_escape_rejected():
    """Protects against backslash traversal and nested paths escaping skill root."""
    def run(_base_dir):
        backslash_result = load_runtime_skill("..\\passive_recon")
        nested_result = load_runtime_skill("safe/../../passive_recon")

        assert_true(backslash_result["loaded"] is False, "Backslash traversal should be rejected")
        assert_true(backslash_result["path"] is None, "Backslash traversal should not expose path")
        assert_true(nested_result["loaded"] is False, "Nested escape path should be rejected")
        assert_true(nested_result["path"] is None, "Nested escape path should not expose path")

    with_temp_skill_dir(run)


def test_loader_returns_text_without_executing_content():
    """Protects the boundary that SKILL.md content is returned, never executed."""
    def run(base_dir):
        marker = base_dir / "executed.txt"
        content = (
            "# Text Only\n\n"
            "This looks like code but must remain inert:\n"
            "```python\n"
            f"Path({str(marker)!r}).write_text('executed')\n"
            "```\n"
        )
        create_skill(base_dir, "text_only", content)

        result = load_runtime_skill("text_only")

        assert_true(result["loaded"] is True, "Text-only skill should load")
        assert_true("write_text" in result["content"], "Potential code should be returned as text")
        assert_true(marker.exists() is False, "Loader must not execute skill content")

    with_temp_skill_dir(run)


if __name__ == "__main__":
    test_load_existing_skill()
    test_missing_skill_returns_loaded_false()
    test_path_traversal_rejected()
    test_absolute_path_rejected()
    test_backslash_and_nested_escape_rejected()
    test_loader_returns_text_without_executing_content()

    print("All skill loader tests passed.")
