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
REQUIRED_LIST_FIELDS = {
    "veille": ("fortinet", "cyber", "kev"),
    "community": ("topics", "incidents"),
}


def read_json(path):
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in SOURCE_FILES:
        raise SystemExit("Usage: update_health.py veille|community")

    source = sys.argv[1]
    now = datetime.now(timezone.utc).isoformat()
    workflow_status = os.environ.get("WORKFLOW_STATUS", "failure").lower()
    run_url = os.environ.get("RUN_URL", "https://github.com/Riiddiimz/Automatik/actions")
    existing = read_json(HEALTH_FILES[source]) or {}
    dataset = read_json(SOURCE_FILES[source])
    schema_errors = []

    if dataset is None:
        schema_errors.append(
            f"Le fichier {SOURCE_FILES[source].name} est absent, invalide ou ne contient pas un objet JSON."
        )
        errors = []
        is_partial = False
    else:
        missing_fields = [
            field for field in REQUIRED_LIST_FIELDS[source]
            if not isinstance(dataset.get(field), list)
        ]
        if missing_fields:
            schema_errors.append(
                "Structure invalide : les champs suivants doivent être des tableaux : "
                + ", ".join(missing_fields)
                + "."
            )

        raw_errors = dataset.get("errors", [])
        if not isinstance(raw_errors, list):
            schema_errors.append("Le champ errors doit être un tableau.")
            raw_errors = []
        errors = [str(error) for error in raw_errors if error]

        if "partial" in dataset and not isinstance(dataset["partial"], bool):
            schema_errors.append("Le champ partial doit être un booléen.")
        is_partial = dataset.get("partial") is True or bool(errors)

    if workflow_status != "success":
        status = "error"
        message = "Le workflow GitHub Actions a échoué. Les dernières données publiées sont conservées, mais peuvent être anciennes."
    elif schema_errors:
        status = "error"
        message = "Le workflow a terminé, mais le jeu de données est invalide : " + " ".join(schema_errors)
    elif is_partial:
        status = "partial"
        details = " ".join(errors[:2]) or "la collecte a signalé un état partiel."
        message = "La collecte s'est exécutée, mais certaines sources sont incomplètes : " + details
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
