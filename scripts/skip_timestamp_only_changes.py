#!/usr/bin/env python3
"""Avoid publishing a new static-site build when only volatile timestamps changed."""
from __future__ import annotations

import argparse
import copy
import json
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DATASETS = {
    "data/veille.json": "veille",
    "data/community.json": "community",
}


def normalized_snapshot(data: dict[str, Any], dataset: str) -> dict[str, Any]:
    """Remove timestamps that describe a collection attempt, not changed content."""
    snapshot = copy.deepcopy(data)
    if dataset == "veille":
        snapshot.pop("generatedAt", None)
    elif dataset == "community":
        for key in ("generatedAt", "synthesisGeneratedAt", "aiReviewGeneratedAt"):
            snapshot.pop(key, None)
        for topic in snapshot.get("topics", []):
            if isinstance(topic, dict):
                topic.pop("lastSeen", None)
        for incident in snapshot.get("incidents", []):
            if not isinstance(incident, dict):
                continue
            review = incident.get("aiReview")
            if isinstance(review, dict):
                review.pop("reviewedAt", None)
    else:
        raise ValueError(f"Type de jeu de données inconnu : {dataset}")
    return snapshot


def same_published_content(previous: dict[str, Any], current: dict[str, Any], dataset: str) -> bool:
    """Compare source data, health warnings and rendered content, ignoring volatile times."""
    return normalized_snapshot(previous, dataset) == normalized_snapshot(current, dataset)


def restore_previous_if_only_timestamps_changed(
    target: Path, previous_text: str, dataset: str
) -> bool:
    """Restore the committed bytes when a run changed timestamps but no useful content."""
    previous = json.loads(previous_text)
    current = json.loads(target.read_text(encoding="utf-8"))
    if not same_published_content(previous, current, dataset):
        return False
    target.write_text(previous_text, encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", choices=sorted(DATASETS))
    args = parser.parse_args()
    relative_path = args.path
    target = ROOT / relative_path
    if not target.is_file():
        raise SystemExit(f"Fichier introuvable : {relative_path}")

    previous_run = subprocess.run(
        ["git", "show", f"HEAD:{relative_path}"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    if previous_run.returncode:
        print(f"Aucun snapshot précédent pour {relative_path}; publication initiale conservée.")
        return 0

    if restore_previous_if_only_timestamps_changed(
        target, previous_run.stdout, DATASETS[relative_path]
    ):
        print(
            f"{relative_path}: aucun changement de contenu; horodatages seuls ignorés "
            "pour éviter un déploiement inutile."
        )
    else:
        print(f"{relative_path}: changement de contenu ou d'état détecté; publication conservée.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
