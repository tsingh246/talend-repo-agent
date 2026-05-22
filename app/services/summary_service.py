from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from services.llm_summary_service import (
    LLM_SUMMARY_VERSION,
    build_llm_summary,
    get_llm_summary_model,
    llm_summaries_enabled,
)


COMPONENT_INSTANCE_REGEX = re.compile(r"^(t[A-Z][A-Za-z0-9]*)(?:_\d+)?$")
FILE_OR_BUCKET_REGEX = re.compile(
    r"(?:[A-Za-z]:[\\/][^\s\"'<>]+|/[A-Za-z0-9._/-]+|s3://[A-Za-z0-9._/-]+)",
    re.IGNORECASE,
)
SUMMARY_STYLE_VERSION = "engineering-summary-v4-related-routines"


def build_summary(artifact_type: str, parsed: dict[str, Any]) -> tuple[str, str, str, str]:
    artifact_name = parsed.get("name", "")
    raw_components = parsed.get("component_types", [])
    urls = parsed.get("urls", [])
    context_refs = parsed.get("context_refs", [])
    sql_snippets = parsed.get("sql_snippets", [])
    sql_evidence = parsed.get("sql_evidence", [])
    code_snippets = parsed.get("code_snippets", [])
    method_names = parsed.get("method_names", [])
    imports = parsed.get("imports", [])
    string_literals = parsed.get("string_literals", [])
    code_keywords = parsed.get("code_keywords", [])
    config_signals = parsed.get("config_signals", [])
    auth_signals = parsed.get("auth_signals", [])
    class_names = parsed.get("class_names", [])
    parameter_names = parsed.get("parameter_names", [])
    qualified_class_refs = parsed.get("qualified_class_refs", [])
    job_dependencies = parsed.get("job_dependencies", [])
    related_routines = parsed.get("related_routines", [])

    normalized_components = normalize_summary_components(raw_components)

    if artifact_type == "job":
        summary = build_job_summary(
            artifact_name,
            normalized_components,
            urls,
            context_refs,
            sql_snippets,
            sql_evidence,
            code_snippets,
            config_signals,
            auth_signals,
            related_routines,
        )
    elif artifact_type == "joblet":
        summary = build_joblet_summary(
            artifact_name,
            normalized_components,
            urls,
            context_refs,
            sql_snippets,
            sql_evidence,
            code_snippets,
            config_signals,
            auth_signals,
        )
    elif artifact_type == "routine":
        summary = build_routine_summary(
            artifact_name=artifact_name,
            urls=urls,
            context_refs=context_refs,
            method_names=method_names,
            imports=imports,
            string_literals=string_literals,
            code_keywords=code_keywords,
            class_names=class_names,
            parameter_names=parameter_names,
            qualified_class_refs=qualified_class_refs,
        )
    else:
        summary = "Talend artifact discovered and parsed."

    llm_summary = build_llm_summary(
        artifact_type=artifact_type,
        parsed=parsed,
        deterministic_summary=summary,
    )
    if llm_summary:
        summary = llm_summary

    search_text = build_search_text(
        artifact_type=artifact_type,
        summary=summary,
        normalized_components=normalized_components,
        urls=urls,
        context_refs=context_refs,
        sql_snippets=sql_snippets,
        sql_evidence=sql_evidence,
        method_names=method_names,
        code_keywords=code_keywords,
        config_signals=config_signals,
        auth_signals=auth_signals,
        class_names=class_names,
        parameter_names=parameter_names,
        qualified_class_refs=qualified_class_refs,
        string_literals=string_literals,
        job_dependencies=job_dependencies,
        related_routines=related_routines,
    )

    embedding_text = build_embedding_text(
        artifact_type=artifact_type,
        summary=summary,
        normalized_components=normalized_components,
        urls=urls,
        context_refs=context_refs,
        sql_snippets=sql_snippets,
        sql_evidence=sql_evidence,
        method_names=method_names,
        code_keywords=code_keywords,
        config_signals=config_signals,
        auth_signals=auth_signals,
        class_names=class_names,
        parameter_names=parameter_names,
        qualified_class_refs=qualified_class_refs,
        job_dependencies=job_dependencies,
        related_routines=related_routines,
    )

    component_text = ", ".join(normalized_components[:15])

    return summary, search_text, component_text, embedding_text


def build_artifact_hashes(artifact_type: str, parsed: dict[str, Any]) -> tuple[str, str]:
    raw_components = parsed.get("component_types", [])
    normalized_components = normalize_summary_components(raw_components)
    sql_evidence = parsed.get("sql_evidence", [])
    sql_snippets = parsed.get("sql_snippets", [])
    code_snippets = parsed.get("code_snippets", [])
    method_names = parsed.get("method_names", [])
    code_keywords = parsed.get("code_keywords", [])
    config_signals = parsed.get("config_signals", [])
    auth_signals = parsed.get("auth_signals", [])
    class_names = parsed.get("class_names", [])
    parameter_names = parsed.get("parameter_names", [])
    qualified_class_refs = parsed.get("qualified_class_refs", [])
    job_dependencies = parsed.get("job_dependencies", [])
    related_routines = parsed.get("related_routines", [])
    urls = parsed.get("urls", [])
    context_refs = parsed.get("context_refs", [])
    string_literals = parsed.get("string_literals", [])
    text_samples = parsed.get("text_samples", [])

    functional_payload = {
        "artifact_type": artifact_type,
        "component_types": normalized_components,
        "flow_summary": build_flow_summary(normalized_components, sql_evidence),
        "flow_signals": infer_job_signals(
            normalized_components,
            urls,
            context_refs,
            sql_snippets,
            sql_evidence,
            code_snippets,
        ),
        "sql_signatures": build_sql_hash_signatures(sql_evidence, sql_snippets),
        "routine_method_names": method_names,
        "routine_class_names": class_names,
        "routine_parameter_names": parameter_names,
        "qualified_class_refs": qualified_class_refs,
        "code_keywords": code_keywords,
        "config_signals": config_signals,
        "auth_signals": auth_signals,
        "code_snippets": code_snippets,
        "job_dependencies": job_dependencies,
        "related_routines": build_related_routine_hash_payload(related_routines),
    }

    connectivity_payload = {
        "urls": urls,
        "context_refs": context_refs,
        "database_technology": detect_database_technology(normalized_components),
        "database_keywords": build_database_keywords(normalized_components),
        "sql_tables": extract_sql_tables_from_evidence(sql_evidence),
        "file_paths_or_buckets": extract_file_paths_or_buckets(
            text_samples + string_literals + code_snippets
        ),
        "connection_security_signals": extract_connection_security_signals(
            text_samples + string_literals + code_snippets + urls + context_refs
        ),
        "config_signals": config_signals,
        "auth_signals": auth_signals,
        "related_routine_connectivity": build_related_routine_connectivity_payload(
            related_routines
        ),
    }

    return stable_hash(functional_payload), stable_hash(connectivity_payload)


def build_artifact_evidence(artifact_type: str, parsed: dict[str, Any]) -> dict[str, Any]:
    normalized_components = normalize_summary_components(parsed.get("component_types", []))
    sql_evidence = parsed.get("sql_evidence", [])

    return {
        "artifact_name": parsed.get("name", ""),
        "artifact_type": artifact_type,
        "components": normalized_components[:30],
        "database_technology": detect_database_technology(normalized_components),
        "flow": build_flow_summary(normalized_components, sql_evidence),
        "config_signals": parsed.get("config_signals", [])[:30],
        "auth_signals": parsed.get("auth_signals", [])[:30],
        "context_refs": parsed.get("context_refs", [])[:30],
        "urls": parsed.get("urls", [])[:20],
        "sql": [
            {
                "operation": item.get("operation", ""),
                "tables": item.get("tables", []),
                "component": item.get("component", ""),
                "signature": item.get("signature", ""),
            }
            for item in sql_evidence[:20]
        ],
        "job_dependencies": parsed.get("job_dependencies", [])[:50],
        "related_routines": parsed.get("related_routines", [])[:20],
        "routine": {
            "classes": parsed.get("class_names", [])[:10],
            "methods": parsed.get("method_names", [])[:20],
            "parameters": parsed.get("parameter_names", [])[:30],
            "qualified_refs": parsed.get("qualified_class_refs", [])[:30],
        },
        "code_keywords": parsed.get("code_keywords", [])[:30],
    }


def build_summary_generation_signature() -> dict[str, str]:
    if not llm_summaries_enabled():
        return {"mode": "deterministic", "version": SUMMARY_STYLE_VERSION}

    return {
        "mode": "llm",
        "version": LLM_SUMMARY_VERSION,
        "fallback_version": SUMMARY_STYLE_VERSION,
        "model": get_llm_summary_model(),
    }


def stable_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_sql_hash_signatures(sql_evidence: list[dict], sql_snippets: list[str]) -> list[dict]:
    signatures: list[dict] = []

    for item in sql_evidence:
        signatures.append(
            {
                "operation": item.get("operation", ""),
                "tables": item.get("tables", []),
                "signature": item.get("signature", ""),
            }
        )

    for snippet in sql_snippets:
        signatures.append({"operation": "", "tables": [], "signature": compact_join([snippet])})

    return signatures


def extract_sql_tables_from_evidence(sql_evidence: list[dict]) -> list[str]:
    tables: list[str] = []
    for item in sql_evidence:
        tables.extend(item.get("tables", []))
    return dedupe_keep_order(tables)


def extract_file_paths_or_buckets(values: list[str]) -> list[str]:
    results: list[str] = []
    for value in values:
        results.extend(FILE_OR_BUCKET_REGEX.findall(str(value)))
    return dedupe_keep_order(results)


def extract_connection_security_signals(values: list[str]) -> list[str]:
    signal_words = [
        "auth",
        "credential",
        "jdbc",
        "key",
        "oauth",
        "password",
        "secret",
        "token",
        "username",
    ]
    results: list[str] = []
    blob = " ".join(str(value) for value in values).lower()

    for word in signal_words:
        if word in blob:
            results.append(word)

    return dedupe_keep_order(results)


def build_related_routine_hash_payload(related_routines: list[dict]) -> list[dict]:
    return [
        {
            "name": item.get("name", ""),
            "matched_by": item.get("matched_by", []),
            "classes": item.get("classes", []),
            "methods": item.get("methods", []),
            "config_signals": item.get("config_signals", []),
            "auth_signals": item.get("auth_signals", []),
            "code_keywords": item.get("code_keywords", []),
        }
        for item in related_routines
    ]


def build_related_routine_connectivity_payload(related_routines: list[dict]) -> list[dict]:
    return [
        {
            "name": item.get("name", ""),
            "config_signals": item.get("config_signals", []),
            "auth_signals": item.get("auth_signals", []),
        }
        for item in related_routines
    ]


def build_search_text(
    artifact_type: str,
    summary: str,
    normalized_components: list[str],
    urls: list[str],
    context_refs: list[str],
    sql_snippets: list[str],
    sql_evidence: list[dict],
    method_names: list[str],
    code_keywords: list[str],
    config_signals: list[str],
    auth_signals: list[str],
    class_names: list[str],
    parameter_names: list[str],
    qualified_class_refs: list[str],
    string_literals: list[str],
    job_dependencies: list[dict],
    related_routines: list[dict],
) -> str:
    parts: list[str] = [summary]

    parts.extend(normalized_components[:15])
    parts.extend(build_database_keywords(normalized_components))
    db_tech = detect_database_technology(normalized_components)
    if db_tech:
        parts.append(f"Database technology: {db_tech}.")
    parts.extend(context_refs[:15])
    parts.extend(method_names[:10])
    parts.extend(class_names[:5])
    parts.extend(code_keywords[:15])
    parts.extend(config_signals[:20])
    parts.extend(auth_signals[:20])
    parts.extend(parameter_names[:15])
    parts.extend(shorten_refs(qualified_class_refs[:15]))

    parts.extend(build_sql_search_keywords(sql_evidence))
    parts.extend(build_dependency_search_keywords(job_dependencies))
    parts.extend(build_related_routine_search_keywords(related_routines))

   
    if artifact_type != "routine":
        parts.extend(urls[:8])
        #parts.extend(sql_snippets[:3])
    else:
        parts.extend(filter_string_literals(string_literals[:10]))

    return compact_join(parts)

def build_database_keywords(component_types: list[str]) -> list[str]:
    db_tech = detect_database_technology(component_types)
    if not db_tech:
        return []

    return [f"database_type:{db_tech}", db_tech, db_tech.lower()]

def build_flow_summary(component_types: list[str], sql_evidence: list[dict]) -> str:
    steps = []
    comp_set = set(component_types)

    if any(c in comp_set for c in ["tREST", "tRESTClient", "tRESTRequest", "tHTTPClient"]):
        steps.append("call REST/HTTP endpoint")

    if "tExtractJSONFields" in comp_set:
        steps.append("extract JSON response")

    if "tSetGlobalVar" in comp_set:
        steps.append("store values in global variables")

    if "tRowGenerator" in comp_set or "tFixedFlowInput" in comp_set:
        steps.append("generate records")

    if any(c in comp_set for c in ["tDBInput", "tOracleInput", "tHSQLDbInput", "tPostgresqlInput"]):
        steps.append("read from database")

    if "tMap" in comp_set or "tXMLMap" in comp_set:
        steps.append("transform/map data")

    if any(c in comp_set for c in ["tJava", "tJavaRow", "tJavaFlex"]):
        steps.append("apply custom Java logic")

    if sql_evidence:
        steps.append("run SQL logic")

    if any(c in comp_set for c in ["tDBOutput", "tOracleOutput", "tHSQLDbOutput", "tPostgresqlOutput"]):
        steps.append("write to database")

    if "tLogRow" in comp_set:
        steps.append("log output")

    return " -> ".join(steps)
def build_embedding_text(
    artifact_type: str,
    summary: str,
    normalized_components: list[str],
    urls: list[str],
    context_refs: list[str],
    sql_snippets: list[str],
    sql_evidence: list[dict],
    method_names: list[str],
    code_keywords: list[str],
    config_signals: list[str],
    auth_signals: list[str],
    class_names: list[str],
    parameter_names: list[str],
    qualified_class_refs: list[str],
    job_dependencies: list[dict],
    related_routines: list[dict],
) -> str:
    parts: list[str] = []

    parts.append(f"Artifact type: {artifact_type}")
    parts.append(summary)
    flow_summary = build_flow_summary(normalized_components, sql_evidence)
    if flow_summary:
        parts.append(f"Job Flow: {flow_summary}.")
    if normalized_components:
        parts.append("Main Talend components: " + ", ".join(normalized_components[:10]))
        db_tech = detect_database_technology(normalized_components)
        if db_tech:
            parts.append(f"Database technology: {db_tech}.")

    if method_names:
        parts.append("Routine methods: " + ", ".join(method_names[:8]))

    if class_names:
        parts.append("Routine classes: " + ", ".join(class_names[:5]))

    if code_keywords:
        parts.append("Technical keywords: " + ", ".join(code_keywords[:10]))

    if config_signals:
        parts.append("Configuration/function signals: " + ", ".join(config_signals[:10]))

    if auth_signals:
        parts.append("Authentication signals: " + ", ".join(auth_signals[:8]))

    if parameter_names and artifact_type == "routine":
        parts.append("Routine parameters: " + ", ".join(parameter_names[:10]))

    if qualified_class_refs and artifact_type == "routine":
        parts.append(
            "Referenced classes/libraries: "
            + ", ".join(shorten_refs(qualified_class_refs[:8]))
        )

    if sql_evidence:
        sql_descriptions = []
        for item in sql_evidence[:3]:
            op = item.get("operation", "SQL")
            tables = item.get("tables", [])
            signature = item.get("signature", "")

            details = []
            if "group_concat" in signature:
                details.append("GROUP_CONCAT aggregation")
            if "group by" in signature:
                details.append("GROUP BY batching")
            if "join" in signature:
                details.append("join logic")

            if "where" in signature:
                details.append("filtering")
            if tables:
                base = f"{op} query on {', '.join(tables[:2])} table"
            else:
                base = f"{op} query"
            if details:
                base += " using " + ", ".join(details)
            sql_descriptions.append(base)
        #parts.append("SQL evidence: " + "; ".join(sql_descriptions))
        parts.append("SQL logic: " + "; ".join(sql_descriptions))

    elif sql_snippets:
        parts.append("SQL logic detected.")

    if context_refs:
        parts.append("Context references detected.")

    if urls and artifact_type != "routine":
        parts.append("URL or API-related configuration detected.")

    if job_dependencies:
        parts.append(
            "Runs child jobs through tRunJob: "
            + ", ".join(format_dependency_name(dep) for dep in job_dependencies[:10])
        )

    if related_routines:
        parts.append(
            "Related routines: "
            + "; ".join(format_related_routine_description(item) for item in related_routines[:5])
        )

    return "\n".join(parts)


def build_related_routine_search_keywords(related_routines: list[dict]) -> list[str]:
    keywords = []
    for routine in related_routines:
        keywords.extend(
            [
                "related routine",
                routine.get("name", ""),
                routine.get("summary", ""),
            ]
        )
        keywords.extend(routine.get("matched_by") or [])
        keywords.extend(routine.get("classes") or [])
        keywords.extend(routine.get("methods") or [])
        keywords.extend(routine.get("config_signals") or [])
        keywords.extend(routine.get("auth_signals") or [])
        keywords.extend(routine.get("code_keywords") or [])
    return dedupe_keep_order([item for item in keywords if item])


def format_related_routine_description(routine: dict) -> str:
    name = routine.get("name") or "routine"
    signals = dedupe_keep_order(
        (routine.get("auth_signals") or [])
        + (routine.get("config_signals") or [])
        + (routine.get("code_keywords") or [])
    )
    if signals:
        return f"{name} ({format_plain_list(signals[:5])})"
    return name


def build_dependency_search_keywords(job_dependencies: list[dict]) -> list[str]:
    keywords = []
    for dep in job_dependencies:
        target = dep.get("target_job", "")
        target_project = dep.get("target_project", "")
        component = dep.get("component", "")
        if target:
            keywords.extend(["tRunJob", "job dependency", "child job", target])
            keywords.append(f"runs_job:{target}")
        if target_project:
            keywords.append(f"target_project:{target_project}")
        if component:
            keywords.append(component)
    return keywords


def format_dependency_name(dep: dict) -> str:
    target = dep.get("target_job") or dep.get("target_id") or "unknown job"
    project = dep.get("target_project")
    if project:
        return f"{project}/{target}"
    return target

def build_sql_search_keywords(sql_evidence: list[dict]) -> list[str]:
    keywords = []

    for item in sql_evidence[:5]:
        op = item.get("operation", "")
        tables = item.get("tables", [])
        signature = item.get("signature", "").lower()

        if op:
            keywords.append(f"sql_op:{op}")
            keywords.append(op)

        for table in tables:
            keywords.append(f"sql_table:{table}")
            keywords.append(table)

        if "group_concat" in signature:
            keywords.append("sql_feature:group_concat")
            keywords.append("group_concat")

        if "group by" in signature or "group_by" in signature:
            keywords.append("sql_feature:group_by")
            keywords.append("group by")

        if "where" in signature:
            keywords.append("sql_feature:where_filter")
            keywords.append("where filter")

        if "join" in signature:
            keywords.append("sql_feature:join")
            keywords.append("join")

        keywords.append(signature)

    return keywords
def build_job_summary(
    artifact_name: str,
    component_types: list[str],
    urls: list[str],
    context_refs: list[str],
    sql_snippets: list[str],
    sql_evidence: list[dict],
    code_snippets: list[str],
    config_signals: list[str],
    auth_signals: list[str],
    related_routines: list[dict],
) -> str:
    category = infer_job_category(
        component_types, urls, sql_snippets, sql_evidence, code_snippets, config_signals, auth_signals
    )
    signals = infer_job_signals(
        component_types, urls, context_refs, sql_snippets, sql_evidence, code_snippets
    )
    signals.extend(config_signals[:6])
    signals.extend(auth_signals[:4])
    signals = dedupe_keep_order(signals)
    sql_intent = build_sql_intent(sql_evidence, sql_snippets)
    flow_summary = build_flow_summary(component_types, sql_evidence)
    db_tech = detect_database_technology(component_types)

    subject = f"{artifact_name} is a Talend job" if artifact_name else "This Talend job"
    parts = [f"{subject} for {category}."]
    if flow_summary:
        parts.append(f"At a high level, {describe_flow_as_sentence(flow_summary)}")

    if sql_intent:
        parts.append(sql_intent + ".")

    if db_tech:
        parts.append(f"It works with {db_tech} data.")

    auth_or_config = dedupe_keep_order(config_signals[:4] + auth_signals[:4])
    if auth_or_config:
        parts.append(f"Configuration signals indicate {format_plain_list(auth_or_config[:5])}.")

    related_signals = summarize_related_routine_signals(related_routines)
    if related_signals:
        parts.append(
            "It appears to rely on shared routine logic for "
            + format_plain_list(related_signals[:4])
            + "."
        )

    if signals:
        parts.append(f"Key behavior: {format_plain_list(signals[:5])}.")

    # tRunJob dependencies are appended to embedding/search text separately.

    return " ".join(parts)


def summarize_related_routine_signals(related_routines: list[dict]) -> list[str]:
    signals = []
    for routine in related_routines:
        signals.extend(routine.get("auth_signals") or [])
        signals.extend(routine.get("config_signals") or [])
        signals.extend(routine.get("code_keywords") or [])
    return dedupe_keep_order(signals)


def build_joblet_summary(
    artifact_name: str,
    component_types: list[str],
    urls: list[str],
    context_refs: list[str],
    sql_snippets: list[str],
    sql_evidence: list[dict],
    code_snippets: list[str],
    config_signals: list[str],
    auth_signals: list[str],
) -> str:
    category = infer_joblet_category(component_types, urls, sql_snippets, sql_evidence, code_snippets)
    signals = infer_job_signals(component_types, urls, context_refs, sql_snippets, sql_evidence, code_snippets)
    signals.extend(config_signals[:6])
    signals.extend(auth_signals[:4])
    signals = dedupe_keep_order(signals)
    sql_intent = build_sql_intent(sql_evidence, sql_snippets)
    flow_summary = build_flow_summary(component_types, sql_evidence)

    subject = f"{artifact_name} is a reusable Talend joblet" if artifact_name else "This reusable Talend joblet"
    parts = [f"{subject} for {category}."]
    if flow_summary:
        parts.append(f"At a high level, {describe_flow_as_sentence(flow_summary)}")

    if sql_intent:
        parts.append(sql_intent + ".")

    if signals:
        parts.append(f"Key behavior: {format_plain_list(signals[:5])}.")

    return " ".join(parts)


def build_sql_intent(sql_evidence: list[dict], sql_snippets: list[str]) -> str:
    if sql_evidence:
        item = sql_evidence[0]
        op = item.get("operation", "SQL")
        tables = item.get("tables", [])

        if tables:
            return f"SQL intent: {op} query involving {', '.join(tables[:3])}"
        return f"SQL intent: {op} query detected"

    #if sql_snippets:
       # return "SQL intent: SQL logic detected"

    return ""


def build_routine_summary(
    artifact_name: str,
    urls: list[str],
    context_refs: list[str],
    method_names: list[str],
    imports: list[str],
    string_literals: list[str],
    code_keywords: list[str],
    class_names: list[str],
    parameter_names: list[str],
    qualified_class_refs: list[str],
) -> str:
    category = infer_routine_category(
        urls=urls,
        context_refs=context_refs,
        method_names=method_names,
        imports=imports,
        string_literals=string_literals,
        code_keywords=code_keywords,
        class_names=class_names,
        parameter_names=parameter_names,
        qualified_class_refs=qualified_class_refs,
    )

    routine_name = artifact_name or (class_names[0] if class_names else "This routine")
    parts = [f"{routine_name} is a Talend routine that provides {category}."]

    if class_names:
        parts.append(f"It defines {format_plain_list(class_names[:2])}.")

    if method_names:
        parts.append(f"Important methods include {format_plain_list(method_names[:4])}.")

    if parameter_names:
        parts.append(f"It accepts parameters such as {format_plain_list(parameter_names[:6])}.")

    if code_keywords:
        parts.append(f"The code references {format_plain_list(code_keywords[:6])}.")

    if qualified_class_refs:
        parts.append(f"It uses libraries such as {format_plain_list(shorten_refs(qualified_class_refs[:4]))}.")

    if urls:
        parts.append("It contains URL or API-related configuration.")

    if context_refs:
        parts.append("It reads values from Talend context variables.")

    return " ".join(parts)


def describe_flow_as_sentence(flow_summary: str) -> str:
    steps = [step.strip() for step in flow_summary.split("->") if step.strip()]
    if not steps:
        return "the flow performs integration processing."
    if len(steps) == 1:
        return f"the flow is to {steps[0]}."
    return f"the flow is to {steps[0]}, then " + ", then ".join(steps[1:]) + "."


def infer_job_category(
    component_types: list[str],
    urls: list[str],
    sql_snippets: list[str],
    sql_evidence: list[dict],
    code_snippets: list[str],
    config_signals: list[str],
    auth_signals: list[str],
) -> str:
    comp_set = set(component_types)
    signal_blob = " ".join(config_signals + auth_signals).lower()

    if "hashicorp" in signal_blob or "vault" in signal_blob:
        return "HashiCorp Vault secret management"

    if "snowflake jwt" in signal_blob or "snowflake key pair" in signal_blob:
        return "Snowflake key-pair authentication"

    if "sftp" in signal_blob or "ssh" in signal_blob:
        return "SSH/SFTP file transfer or key-based authentication"

    if {"tRest", "tRESTRequest", "tRESTResponse", "tRESTClient", "tHTTPClient"} & comp_set or urls:
        return "REST API processing"

    if {"tS3Put", "tS3Get", "tS3List", "tS3Connection", "tS3Delete", "tS3Copy"} & comp_set:
        return "AWS S3 processing"

    db_tech = detect_database_technology(component_types)
    if db_tech:
        return f"{db_tech} database processing"

    if {"tExtractJSONFields", "tWriteJSONField"} & comp_set:
        return "JSON processing"

    if {"tDBInput", "tDBOutput", "tDBRow"} & comp_set or sql_snippets or sql_evidence:
        return "database processing"

    if {"tFileInputDelimited", "tFileOutputDelimited", "tFileInputRaw"} & comp_set:
        return "file processing"

    if "tSystem" in comp_set:
        return "system command execution"

    if {"tMap", "tJavaRow"} & comp_set:
        return "data transformation"

    if urls:
        return "URL/API-related processing"

    return "integration processing"


def infer_joblet_category(
    component_types: list[str],
    urls: list[str],
    sql_snippets: list[str],
    sql_evidence: list[dict],
    code_snippets: list[str],
) -> str:
    comp_set = set(component_types)

    if {"tRESTResponse", "tRESTRequest", "tRESTClient"} & comp_set or urls:
        return "REST/API handling"

    if {"tLogRow", "tFlowMeterCatcher"} & comp_set:
        return "logging/monitoring"

    if {"tMap", "tXMLMap"} & comp_set:
        return "transformation"

    if {"tJava", "tJavaRow"} & comp_set or code_snippets:
        return "custom logic"

    if sql_evidence:
        return "database/SQL handling"

    return "reusable processing"


def infer_job_signals(
    component_types: list[str],
    urls: list[str],
    context_refs: list[str],
    sql_snippets: list[str],
    sql_evidence: list[dict],
    code_snippets: list[str],
) -> list[str]:
    signals: list[str] = []
    comp_set = set(component_types)

    if {"tRESTRequest", "tRESTResponse", "tRESTClient"} & comp_set or urls:
        signals.append("REST/API handling")

    if {"tS3Put", "tS3Get", "tS3List", "tS3Connection", "tS3Delete", "tS3Copy"} & comp_set:
        signals.append("AWS S3 handling")

    if {"tExtractJSONFields", "tWriteJSONField"} & comp_set:
        signals.append("JSON handling")

    if {"tXMLMap", "tExtractXMLField"} & comp_set:
        signals.append("XML handling")

    if "tMap" in comp_set:
        signals.append("data mapping")

    if {"tJava", "tJavaRow", "tJavaFlex"} & comp_set or code_snippets:
        signals.append("custom Java logic")

    if sql_snippets or sql_evidence:
        signals.append("SQL logic")

    if context_refs:
        signals.append("context variable usage")

    return signals[:6]


def infer_routine_category(
    urls: list[str],
    context_refs: list[str],
    method_names: list[str],
    imports: list[str],
    string_literals: list[str],
    code_keywords: list[str],
    class_names: list[str],
    parameter_names: list[str],
    qualified_class_refs: list[str],
) -> str:
    signals_blob = " ".join(
        urls
        + context_refs
        + method_names
        + imports
        + string_literals
        + code_keywords
        + class_names
        + parameter_names
        + qualified_class_refs
    ).lower()

    if "hashicorp" in signals_blob or "vault" in signals_blob:
        if "aws" in signals_blob or "iam" in signals_blob:
            return "HashiCorp Vault AWS IAM authentication"
        return "HashiCorp Vault secret management"

    if any(x in signals_blob for x in ["token", "secret", "auth", "password"]):
        return "authentication/secret handling"

    if any(x in signals_blob for x in ["s3", "presigned", "bucket", "aws", "amazon"]):
        return "AWS S3 helper processing"

    if any(x in signals_blob for x in ["http", "https", "api", "rest", "request", "response", "url"]):
        return "API/helper processing"

    if any(x in signals_blob for x in ["json", "xml"]):
        return "data parsing/transformation"

    if any(x in signals_blob for x in ["file", "path", "directory"]):
        return "file/path utility logic"

    if any(x in signals_blob for x in ["oracle", "jdbc", "sql", "query"]):
        return "database/helper processing"

    return "custom utility logic"


def normalize_summary_components(values: list[str]) -> list[str]:
    normalized: list[str] = []

    for value in values:
        v = value.strip()
        match = COMPONENT_INSTANCE_REGEX.match(v)
        if not match:
            continue
        normalized.append(match.group(1))

    return dedupe_keep_order(normalized)


def detect_database_technology(component_types: list[str]) -> str | None:
    db_map = {
        "Oracle": ["tOracleInput", "tOracleOutput", "tOracleConnection"],
        "HSQLDB": ["tHSQLDbInput", "tHSQLDbOutput"],
        "MySQL": ["tMysqlInput", "tMysqlOutput", "tMysqlConnection"],
        "PostgreSQL": ["tPostgresqlInput", "tPostgresqlOutput", "tPostgresqlConnection"],
        "MSSQL": ["tMSSqlInput", "tMSSqlOutput", "tMSSqlConnection"],
        "Snowflake": ["tSnowflakeInput", "tSnowflakeOutput", "tSnowflakeConnection"],
        "Salesforce": ["tSalesforceInput", "tSalesforceOutput", "tSalesforceConnection"],
    }

    comp_set = set(component_types)

    for db_name, indicators in db_map.items():
        if any(indicator in comp_set for indicator in indicators):
            return db_name

    return None


def filter_string_literals(values: list[str]) -> list[str]:
    cleaned: list[str] = []
    noisy_markers = [
        "user specification",
        "{talendtypes}",
        "{category}",
        "{param}",
        "{example}",
    ]

    for value in values:
        v = value.strip()
        if not v:
            continue
        lower = v.lower()
        if any(marker in lower for marker in noisy_markers):
            continue
        cleaned.append(v)

    return cleaned


def shorten_refs(values: list[str]) -> list[str]:
    result = []
    for value in values:
        parts = value.split(".")
        result.append(parts[-1] if parts else value)
    return result


def compact_join(values: list[str]) -> str:
    seen = set()
    output = []

    for value in values:
        v = " ".join(str(value).split()).strip()
        if not v:
            continue

        lower = v.lower()
        if lower in seen:
            continue

        seen.add(lower)
        output.append(v)

    return " ".join(output)


def format_plain_list(values: list[str]) -> str:
    if not values:
        return ""
    if len(values) == 1:
        return values[0]
    if len(values) == 2:
        return f"{values[0]} and {values[1]}"
    return ", ".join(values[:-1]) + f", and {values[-1]}"


def format_component_list(components: list[str]) -> str:
    if not components:
        return ""

    if len(components) == 1:
        return f"component {components[0]}"

    if len(components) == 2:
        return f"components {components[0]} and {components[1]}"

    return "components " + ", ".join(components[:-1]) + f", and {components[-1]}"


def dedupe_keep_order(values: list[str]) -> list[str]:
    seen = set()
    result = []

    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)

    return result
