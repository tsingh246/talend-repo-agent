from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from catalog_scanner import run_catalog_scan
from db.session import SessionLocal
from repositories.catalog_repository import (
    artifact_lookup,
    create_catalog_scan,
    finish_catalog_scan,
    latest_catalog_scan,
    replace_catalog_findings,
)

CATALOG_INPUT_PATH = Path("data/repos")


def run_data_catalog_scan(input_path: Path | str = CATALOG_INPUT_PATH) -> dict:
    result = run_catalog_scan(input_path)
    with SessionLocal() as db:
        latest = latest_catalog_scan(db, result.input_path)
        if latest and latest.scan_hash == result.scan_hash and latest.status == "complete":
            return {
                "processed": 0,
                "skipped_unchanged": 1,
                "findings": latest.finding_count,
                "failed": 0,
            }

        scan = create_catalog_scan(db, result.input_path, result.input_type, result.scan_hash)
        lookup = artifact_lookup(db)
        rows = []
        for finding in result.findings:
            artifact = lookup.get(finding.file_path.replace("\\", "/").lower())
            rows.append(
                {
                    "artifact_id": artifact.id if artifact else None,
                    "repo_name": finding.repo_name,
                    "project_name": finding.project_name,
                    "job_name": finding.job_name,
                    "artifact_type": finding.artifact_type,
                    "file_path": finding.file_path,
                    "component_name": finding.component_name,
                    "component_type": finding.component_type,
                    "source_type": finding.source_type,
                    "direction": finding.direction,
                    "field_name": finding.field_name,
                    "normalized_field_name": finding.normalized_field_name,
                    "semantic_labels_json": json.dumps(finding.semantic_labels),
                    "pii_category": finding.pii_category,
                    "table_name": finding.table_name,
                    "evidence_text": finding.evidence_text,
                    "confidence": finding.confidence,
                }
            )
        replace_catalog_findings(db, scan.id, rows)
        finish_catalog_scan(db, scan.id, "complete", len(rows))

    return {
        "processed": 1,
        "skipped_unchanged": 0,
        "findings": len(result.findings),
        "failed": 0,
    }
