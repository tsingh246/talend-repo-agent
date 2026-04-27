from __future__ import annotations

import logging

from db.session import SessionLocal
from parsers.item_parser import parse_item_file
from repositories.artifact_repository import (
    get_artifacts_for_summarization,
    update_artifact_summary,
)
from services.summary_service import build_summary

logger = logging.getLogger(__name__)


def summarize_all_artifacts() -> tuple[int, int]:
    processed = 0
    failed = 0

    with SessionLocal() as db:
        artifacts = get_artifacts_for_summarization(db)

    for artifact in artifacts:
        try:
            parsed = parse_item_file(artifact.file_path, artifact.artifact_type)
            # Preserve artifact name for richer summary/embedding content.
            parsed["name"] = artifact.name
            summary, search_text, component_text, embedding_text = build_summary(
                artifact.artifact_type, parsed
            )

            with SessionLocal() as db:
                update_artifact_summary(
                    db=db,
                    artifact_id=artifact.id,
                    summary=summary,
                    search_text=search_text,
                    component_types=component_text,
                    embedding_text=embedding_text,
                )

            processed += 1
        except Exception:
            logger.exception(
                "Failed to summarize artifact id=%s path=%s type=%s",
                artifact.id,
                artifact.file_path,
                artifact.artifact_type,
            )
            failed += 1

    return processed, failed