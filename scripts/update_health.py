#!/usr/bin/env python3
"""Publish the last GitHub Actions collection status for the website."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE_FILES = {
    "veille": ROOT / "data" / "veille.json",
    "community": ROOT / "data" / "community.json",
}
HEALTH_FILES = {
    "veille": ROOT / "data" / "health-veille.json",
    "community": ROOT / "data" / "health-community.json",
}
LABELS = {
    "veille": "Veille cyber officielle",
    "community": "Fortinet Community",
}


def read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in SOURCE_FILES:
        raise SystemExit("Usage: update_health.py veille|community")

    source = sys.argv[1]
    now = datetime.now(timezone.utc).isoformat()
    workflow_status = os.environ.get("WORKFLOW_STATUS", "failure").lower()
    run_url = os.environ.get("RUN_URL", "https://github.com/Riiddiimz/Automatik/actions")
    existing = read_json(HEALTH_FILES[source])
    dataset = read_json(SOURCE_FILES[source])
    errors = [str(error) for error in dataset.get("errors", []) if error]
    is_partial = bool(dataset.get("partial") or errors)

    if workflow_status != "success":
        status = "error"
        message = "Le workflow GitHub Actions a échoué. Les dernières données publiées sont conservées, mais peuvent être anciennes."
    elif is_partial:
        status = "partial"
        message = "La collecte s'est exécutée, mais certaines sources sont incomplètes : " + " ".join(errors[:2])
    else:
        status = "ok"
        message = "La collecte s'est terminée sans erreur."
        existing["lastSuccessAt"] = now

    existing.update({
        "source": source,
        "label": LABELS[source],
        "status": status,
        "checkedAt": now,
        "message": message,
        "runUrl": run_url,
    })
    HEALTH_FILES[source].write_text(
        json.dumps(existing, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(f"{LABELS[source]}: {status} ({now})")


if __name__ == "__main__":
    main()
