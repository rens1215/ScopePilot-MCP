import json
from datetime import datetime, timezone
from pathlib import Path


FINDINGS_FILE = Path(__file__).resolve().parent.parent / "data" / "findings.jsonl"


def save_finding(finding: dict) -> dict:
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "finding": finding
    }

    with open(FINDINGS_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")

    return {
        "saved": True,
        "path": str(FINDINGS_FILE),
        "record": record
    }


def load_findings(limit: int = 50) -> list[dict]:
    if not FINDINGS_FILE.exists():
        return []

    lines = FINDINGS_FILE.read_text(encoding="utf-8").splitlines()
    records = []

    for line in lines[-limit:]:
        try:
            records.append(json.loads(line))
        except Exception:
            continue

    return records