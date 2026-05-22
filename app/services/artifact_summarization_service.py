from __future__ import annotations

import json
import logging

from db.session import SessionLocal
from parsers.item_parser import parse_item_file
from repositories.artifact_repository import (
    get_artifacts_for_summarization,
    get_routine_artifacts,
    update_artifact_hashes,
    update_artifact_summary,
)
from services.llm_summary_service import llm_summaries_enabled
from services.summary_service import (
    build_artifact_evidence,
    build_artifact_hashes,
    build_summary_generation_signature,
    build_summary,
    stable_hash,
)

logger = logging.getLogger(__name__)
DISCOVERED_SUMMARY = "Discovered artifact (not parsed yet)"


def summarize_all_artifacts() -> tuple[int, int, int]:
    processed = 0
    skipped_unchanged = 0
    failed = 0
    current_summary_status = build_current_summary_status()

    with SessionLocal() as db:
        artifacts = get_artifacts_for_summarization(db)
        routine_index = build_routine_index(get_routine_artifacts(db))

    for artifact in artifacts:
        try:
            parsed = parse_item_file(artifact.file_path, artifact.artifact_type)
            # Preserve artifact name for richer summary/embedding content.
            parsed["name"] = artifact.name
            if artifact.artifact_type == "job":
                parsed["related_routines"] = find_related_routines(parsed, routine_index)

            functional_hash, connectivity_hash = build_artifact_hashes(
                artifact.artifact_type, parsed
            )

            if (
                artifact.functional_hash == functional_hash
                and artifact.summary_status == current_summary_status
            ):
                with SessionLocal() as db:
                    update_artifact_hashes(
                        db=db,
                        artifact_id=artifact.id,
                        functional_hash=functional_hash,
                        connectivity_hash=connectivity_hash,
                        summary_status=current_summary_status,
                    )
                skipped_unchanged += 1
                continue

            if (
                artifact.functional_hash is None
                and has_existing_summary(artifact)
                and not llm_summaries_enabled()
                and artifact.summary_status == current_summary_status
            ):
                with SessionLocal() as db:
                    update_artifact_hashes(
                        db=db,
                        artifact_id=artifact.id,
                        functional_hash=functional_hash,
                        connectivity_hash=connectivity_hash,
                        summary_status=current_summary_status,
                    )
                skipped_unchanged += 1
                continue

            summary, search_text, component_text, embedding_text = build_summary(
                artifact.artifact_type, parsed
            )
            evidence = build_artifact_evidence(artifact.artifact_type, parsed)

            with SessionLocal() as db:
                update_artifact_summary(
                    db=db,
                    artifact_id=artifact.id,
                    summary=summary,
                    search_text=search_text,
                    component_types=component_text,
                    embedding_text=embedding_text,
                    functional_hash=functional_hash,
                    connectivity_hash=connectivity_hash,
                    job_dependencies=parsed.get("job_dependencies", []),
                    evidence=evidence,
                    summary_status=current_summary_status,
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

    return processed, skipped_unchanged, failed


def has_existing_summary(artifact) -> bool:
    summary = (artifact.summary or "").strip()
    return bool(summary and summary != DISCOVERED_SUMMARY and artifact.embedding_text)


def build_current_summary_status() -> str:
    signature = build_summary_generation_signature()
    signature_hash = stable_hash(signature)[:12]
    return f"complete:{signature_hash}"


def build_routine_index(routines) -> list[dict]:
    indexed = []
    for routine in routines:
        parsed = parse_item_file(routine.file_path, "routine")
        evidence = parse_json_object(routine.evidence_json)
        routine_evidence = evidence.get("routine") or {}
        classes = routine_evidence.get("classes") or parsed.get("class_names") or []
        methods = routine_evidence.get("methods") or parsed.get("method_names") or []
        config_signals = evidence.get("config_signals") or parsed.get("config_signals") or []
        auth_signals = evidence.get("auth_signals") or parsed.get("auth_signals") or []
        code_keywords = evidence.get("code_keywords") or parsed.get("code_keywords") or []
        base_name = routine.name.rsplit("_", 1)[0]
        indexed.append(
            {
                "id": routine.id,
                "name": routine.name,
                "base_name": base_name,
                "summary": routine.summary or "",
                "classes": classes,
                "methods": methods,
                "config_signals": config_signals,
                "auth_signals": auth_signals,
                "code_keywords": code_keywords,
            }
        )
    return indexed


def find_related_routines(parsed: dict, routine_index: list[dict]) -> list[dict]:
    if not routine_index:
        return []

    searchable_text = " ".join(
        str(value)
        for key in [
            "code_snippets",
            "text_samples",
            "string_literals",
            "config_signals",
            "auth_signals",
            "context_refs",
            "urls",
        ]
        for value in parsed.get(key, [])
    ).lower()

    related = []
    for routine in routine_index:
        candidates = [routine["base_name"], routine["name"], *routine["classes"]]
        matched_by = dedupe_keep_order([
            candidate
            for candidate in candidates
            if candidate and candidate.lower() in searchable_text
        ])
        if not matched_by:
            continue

        related.append(
            {
                "artifact_id": routine["id"],
                "name": routine["name"],
                "matched_by": matched_by[:5],
                "summary": routine["summary"][:500],
                "classes": routine["classes"][:5],
                "methods": routine["methods"][:8],
                "config_signals": routine["config_signals"][:10],
                "auth_signals": routine["auth_signals"][:10],
                "code_keywords": routine["code_keywords"][:10],
            }
        )

    return related[:20]


def parse_json_object(raw_value: str | None) -> dict:
    if not raw_value:
        return {}
    try:
        value = json.loads(raw_value)
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def dedupe_keep_order(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result
