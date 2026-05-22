from __future__ import annotations

import os
from typing import Any


LLM_SUMMARY_VERSION = "llm-engineering-summary-v2"


def llm_summaries_enabled() -> bool:
    return os.getenv("ENABLE_LLM_SUMMARIES", "").strip().lower() in {"1", "true", "yes"}


def get_llm_summary_model() -> str:
    return os.getenv("OPENAI_SUMMARY_MODEL", "gpt-4o-mini")


def build_llm_summary(
    artifact_type: str,
    parsed: dict[str, Any],
    deterministic_summary: str,
) -> str | None:
    if not llm_summaries_enabled():
        return None
    if not os.getenv("OPENAI_API_KEY"):
        return None

    evidence = build_summary_evidence(artifact_type, parsed, deterministic_summary)
    if not evidence.strip():
        return None

    try:
        from openai import OpenAI
    except Exception:
        return None

    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
    try:
        response = client.chat.completions.create(
            model=get_llm_summary_model(),
            temperature=0,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You summarize Talend repository artifacts for a technical knowledge base. "
                        "Use only the provided evidence. Do not invent systems, tables, endpoints, "
                        "or business purpose. Write concise engineering-focused plain English. "
                        "Do not list Talend component names; describe the behavior instead."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        "Create a high-level summary of this Talend artifact in 2-4 sentences. "
                        "Explain the likely flow and purpose. Mention important authentication, "
                        "database, API, file, or routine behavior only when evidence is present. "
                        "Avoid component inventories and keep implementation evidence for the "
                        "technical evidence sections.\n\n"
                        f"{evidence}"
                    ),
                },
            ],
        )
    except Exception:
        return None

    content = response.choices[0].message.content if response.choices else ""
    return clean_llm_summary(content)


def build_summary_evidence(
    artifact_type: str,
    parsed: dict[str, Any],
    deterministic_summary: str,
) -> str:
    sql_evidence = parsed.get("sql_evidence", [])
    sql_lines = []
    for item in sql_evidence[:5]:
        op = item.get("operation", "SQL")
        tables = item.get("tables", [])
        signature = item.get("signature", "")
        if tables:
            sql_lines.append(f"{op} involving {', '.join(tables[:3])}")
        elif signature:
            sql_lines.append(f"{op} logic detected")

    fields = {
        "artifact_name": parsed.get("name", ""),
        "artifact_type": artifact_type,
        "deterministic_summary": deterministic_summary,
        "components": parsed.get("component_types", [])[:15],
        "config_signals": parsed.get("config_signals", [])[:12],
        "auth_signals": parsed.get("auth_signals", [])[:12],
        "context_refs": parsed.get("context_refs", [])[:12],
        "sql_evidence": sql_lines,
        "routine_classes": parsed.get("class_names", [])[:8],
        "routine_methods": parsed.get("method_names", [])[:12],
        "routine_parameters": parsed.get("parameter_names", [])[:12],
        "qualified_class_refs": parsed.get("qualified_class_refs", [])[:10],
        "code_keywords": parsed.get("code_keywords", [])[:12],
        "job_dependencies": [
            format_dependency_evidence(dep)
            for dep in parsed.get("job_dependencies", [])[:12]
        ],
        "related_routines": [
            format_related_routine_evidence(routine)
            for routine in parsed.get("related_routines", [])[:8]
        ],
    }

    lines = []
    for key, value in fields.items():
        if not value:
            continue
        if isinstance(value, list):
            value = ", ".join(str(item) for item in value if item)
        lines.append(f"{key}: {value}")

    return "\n".join(lines)


def format_dependency_evidence(dep: dict) -> str:
    target = dep.get("target_job") or dep.get("target_id") or "unknown job"
    component = dep.get("component") or "tRunJob"
    context = dep.get("context")
    version = dep.get("version")
    parts = [f"{component} runs {target}"]
    if context:
        parts.append(f"context {context}")
    if version:
        parts.append(f"version {version}")
    return " ".join(parts)


def format_related_routine_evidence(routine: dict) -> str:
    signals = (
        (routine.get("auth_signals") or [])
        + (routine.get("config_signals") or [])
        + (routine.get("code_keywords") or [])
    )
    parts = [routine.get("name") or "related routine"]
    if signals:
        parts.append("signals " + ", ".join(str(item) for item in signals[:8]))
    if routine.get("matched_by"):
        parts.append("matched by " + ", ".join(str(item) for item in routine["matched_by"][:4]))
    return " ".join(parts)


def clean_llm_summary(value: str | None) -> str | None:
    summary = " ".join(str(value or "").split())
    if not summary:
        return None
    return summary[:1200]
