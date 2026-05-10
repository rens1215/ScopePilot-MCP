from datetime import datetime
from pathlib import Path


LOG_FILE = Path(__file__).resolve().parent.parent / "data" / "mcp.log"


def log_event(message: str) -> None:
    timestamp = datetime.now().isoformat()

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {message}\n")