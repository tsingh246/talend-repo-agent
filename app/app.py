import streamlit as st
import re
import json
import csv
import html
import io
import base64
import xml.etree.ElementTree as ET
from pathlib import Path

from db.init_db import init_db
from db.session import SessionLocal
from services.scan_service import scan_repositories
from services.artifact_summarization_service import (
    build_current_summary_status,
    summarize_all_artifacts,
)
from services.catalog_scan_service import run_data_catalog_scan
from services.semantic_search_service import (
    build_embedding_source_hash,
    build_missing_embeddings,
    build_semantic_document,
    get_embedding_provider,
    get_openai_embedding_model_identifier,
    get_sentence_transformer_model_name,
    semantic_search_artifacts,
    semantic_search_artifacts_pgvector,
)
from services.vulnerability_scan_service import run_vulnerability_input_scan, run_vulnerability_scan
from repositories.artifact_repository import (
    create_sample_artifacts,
    find_artifact_by_job_name,
    get_all_artifacts,
    get_artifact_by_id,
    insert_artifacts,
    search_artifacts,
)
from repositories.vulnerability_repository import (
    finding_to_dict,
    get_all_vulnerability_findings,
    get_artifacts_with_vulnerability_findings,
    get_vulnerability_findings_for_artifact,
)
from repositories.catalog_repository import (
    catalog_finding_to_dict,
    get_catalog_filter_options,
    get_catalog_findings,
    parse_json_list,
    search_catalog_findings,
)
st.set_page_config(page_title="Talend Knowledge Base", layout="wide")

st.title("Talend Knowledge Base")
st.caption("Search Talend jobs, routines, dependencies, and technical evidence.")

MATCH_EVIDENCE_FIELDS = [
    {
        "key": "name",
        "label": "Name",
        "reason_label": "name",
        "kind": "text",
        "getter": lambda artifact, evidence: artifact.name,
    },
    {
        "key": "summary",
        "label": "Summary",
        "reason_label": "summary",
        "kind": "text",
        "getter": lambda artifact, evidence: artifact.summary,
    },
    {
        "key": "path",
        "label": "File path",
        "reason_label": "path",
        "kind": "text",
        "getter": lambda artifact, evidence: artifact.file_path,
    },
    {
        "key": "components",
        "label": "Components",
        "reason_label": "component",
        "kind": "list",
        "getter": lambda artifact, evidence: split_component_text(artifact.component_types),
    },
    {
        "key": "auth_signals",
        "label": "Authentication",
        "reason_label": "auth",
        "kind": "list",
        "getter": lambda artifact, evidence: evidence.get("auth_signals") or [],
    },
    {
        "key": "config_signals",
        "label": "Config / Function",
        "reason_label": "config",
        "kind": "list",
        "getter": lambda artifact, evidence: evidence.get("config_signals") or [],
    },
    {
        "key": "context_refs",
        "label": "Context variables",
        "reason_label": "context",
        "kind": "list",
        "getter": lambda artifact, evidence: evidence.get("context_refs") or [],
    },
    {
        "key": "urls",
        "label": "URLs / endpoints",
        "reason_label": "url",
        "kind": "list",
        "getter": lambda artifact, evidence: evidence.get("urls") or [],
    },
    {
        "key": "sql_tables",
        "label": "SQL tables",
        "reason_label": "sql table",
        "kind": "list",
        "getter": lambda artifact, evidence: extract_sql_tables_for_export(evidence),
    },
    {
        "key": "job_dependencies",
        "label": "Job dependencies",
        "kind": "custom",
        "matcher": lambda artifact, evidence, query_terms: match_dependency_evidence(evidence, query_terms),
    },
    {
        "key": "related_routines",
        "label": "Related routines",
        "kind": "custom",
        "matcher": lambda artifact, evidence, query_terms: match_related_routine_evidence(evidence, query_terms),
    },
    {
        "key": "vulnerability_scan",
        "label": "Vulnerability scan",
        "kind": "custom",
        "matcher": lambda artifact, evidence, query_terms: match_vulnerability_scan_evidence(artifact, evidence, query_terms),
    },
]

DEFAULT_MATCH_EVIDENCE_FIELDS = [
    "name",
    "components",
    "auth_signals",
    "config_signals",
    "context_refs",
    "urls",
    "sql_tables",
    "job_dependencies",
    "related_routines",
    "vulnerability_scan",
    "summary",
]

try:
    init_db()
except Exception as e:
    st.error(f"Database initialization failed: {e}")
    st.stop()


def extract_sql_search_signature(search_text: str | None) -> str:
    if not search_text:
        return ""
    for token in str(search_text).split():
        if token.startswith("sql_preview_"):
            return token.replace("sql_preview_", "").replace("_", " ")
    return ""


def render_artifacts(
    artifacts,
    query: str = "",
    filters: dict | None = None,
    scores: dict[int, float] | None = None,
) -> None:
    if not artifacts:
        st.info("No artifacts found.")
        return
    scores = scores or {}

    for artifact in artifacts:
        with st.container():
            st.subheader(artifact.name)
            if artifact.id in scores:
                st.write(f"**Semantic Score:** {scores[artifact.id]:.3f}")
            st.caption(
                f"{artifact.artifact_type} | {artifact.project_name or ''} | "
                f"{artifact.repo_name}"
            )
            st.write(f"**Summary:** {artifact.summary}")
            match_evidence = build_match_evidence(artifact, query, filters or {})
            if match_evidence:
                st.caption("Why matched: " + " | ".join(match_evidence[:5]))
            if st.button("View details", key=f"view-artifact-{artifact.id}"):
                st.session_state["selected_artifact_id"] = artifact.id
                st.rerun()
            st.divider()


def render_vulnerability_results() -> None:
    with SessionLocal() as db:
        affected_artifacts = get_artifacts_with_vulnerability_findings(db)
        all_findings = get_all_vulnerability_findings(db)
        export_rows = build_vulnerability_export_rows()
    external_findings = [finding for finding in all_findings if finding.artifact_id is None]

    st.subheader("Vulnerability Scan Results")
    st.caption(
        f"{len(affected_artifacts)} artifact(s) and {len(external_findings)} external finding(s)"
    )

    st.download_button(
        "Download Vulnerability CSV",
        data=build_csv_export(export_rows),
        file_name="talend_vulnerability_scan_results.csv",
        mime="text/csv",
        disabled=not export_rows,
    )

    if not affected_artifacts:
        st.info("No KB artifacts have vulnerable Maven dependencies stored.")

    for artifact in affected_artifacts:
        vulnerabilities = get_artifact_vulnerabilities(artifact)
        highest_severity = summarize_vulnerability_severity(vulnerabilities)
        with st.container():
            st.subheader(artifact.name)
            st.caption(
                f"{artifact.artifact_type} | {artifact.project_name or ''} | "
                f"{artifact.repo_name}"
            )
            st.write(f"**Path:** {artifact.file_path}")
            st.write(f"**Summary:** {artifact.summary or ''}")
            st.write(
                f"**Vulnerable jars:** {len(vulnerabilities)}"
                + (f" | **Highest severity:** {highest_severity}" if highest_severity else "")
            )
            for vuln in vulnerabilities[:5]:
                jar = f"{vuln.get('package', '')}:{vuln.get('current_version', '')}"
                issue = vuln.get("vulnerability_id") or vuln.get("osv_id") or "vulnerability"
                fix = vuln.get("recommended_fix") or "Review advisory."
                st.write(f"- `{jar}` | {issue} | {fix}")
            if st.button("View details", key=f"view-vuln-artifact-{artifact.id}"):
                st.session_state["selected_artifact_id"] = artifact.id
                st.session_state["app_section"] = "Knowledge Base"
                st.rerun()
            st.divider()

    if external_findings:
        st.subheader("External / Standalone Findings")
        rows = []
        for finding in external_findings[:200]:
            rows.append(
                {
                    "Input": finding.project_name or "",
                    "Job/Folder": finding.artifact_name,
                    "Jar": f"{finding.package_name}:{finding.current_version}",
                    "Severity": finding.severity or "",
                    "Issue": finding.vulnerability_id or finding.osv_id or "",
                    "Fix": finding.recommended_fix or "",
                    "Source": finding.source_jar or finding.source_pom or finding.file_path,
                }
            )
        st.dataframe(rows, use_container_width=True, hide_index=True)


def render_vulnerability_page() -> None:
    st.subheader("Vulnerability Scan")
    st.caption("Scan Talend poms, exported jobs, or jar folders and store findings separately from KB artifacts.")

    action_col, input_col = st.columns(2)
    with action_col:
        st.write("**Scan KB Repositories**")
        st.caption("Scans projects under data/repos when a project has a poms folder.")
        if st.button("Run Vulnerability Scan", use_container_width=True):
            try:
                stats = run_vulnerability_scan()
                st.success(
                    "Vulnerability scan complete. "
                    f"Projects: {stats['projects_scanned']}, "
                    f"With poms: {stats['projects_with_poms']}, "
                    f"Dependencies: {stats['dependencies_found']}, "
                    f"Vulnerabilities: {stats['vulnerabilities_found']}, "
                    f"Skipped unchanged: {stats['skipped_unchanged']}, "
                    f"Artifacts updated: {stats['artifacts_updated']}"
                )
                if stats["osv_errors"]:
                    st.warning(
                        "OSV lookup had errors for one or more projects. "
                        "Local poms and Studio patch info were still captured."
                    )
            except Exception as e:
                st.error(f"Vulnerability scan failed: {e}")

    with input_col:
        st.write("**Scan Vulnerability Input Folder**")
        st.caption("Drop exported jobs or jars into data/vulnerability_scan.")
        if st.button("Scan Vulnerability Input Folder", use_container_width=True):
            try:
                stats = run_vulnerability_input_scan()
                st.success(
                    "Vulnerability input scan complete. "
                    f"Dependencies: {stats['dependencies_found']}, "
                    f"Vulnerabilities: {stats['vulnerabilities_found']}, "
                    f"Skipped unchanged: {stats['skipped_unchanged']}"
                )
            except Exception as e:
                st.error(f"Vulnerability input scan failed: {e}")

    st.divider()
    render_vulnerability_results()


def get_artifact_vulnerabilities(artifact) -> list[dict]:
    with SessionLocal() as db:
        findings = get_vulnerability_findings_for_artifact(db, artifact.id)
        return [finding_to_dict(finding) for finding in findings]


def summarize_vulnerability_severity(vulnerabilities: list[dict]) -> str:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    severities = {str(vuln.get("severity") or "UNKNOWN").upper() for vuln in vulnerabilities}
    return next((severity for severity in order if severity in severities), "")


def render_artifact_detail(artifact) -> None:
    st.subheader(artifact.name)
    if st.button("Back to results"):
        st.session_state["selected_artifact_id"] = None
        st.rerun()

    meta_cols = st.columns(4)
    meta_cols[0].metric("Type", artifact.artifact_type)
    meta_cols[1].metric("Project", artifact.project_name or "")
    meta_cols[2].metric("Repo", artifact.repo_name)
    meta_cols[3].metric("Status", format_summary_status(artifact.summary_status))

    st.write(f"**File Path:** {artifact.file_path}")
    st.write("**Summary:**")
    st.write(artifact.summary or "")

    render_job_flow_preview(artifact)
    render_artifact_blueprint(artifact)
    render_job_dependencies(artifact)
    render_artifact_evidence(artifact)

    with st.expander("Search and Embedding Text"):
        sql_signature = extract_sql_search_signature(artifact.search_text)
        if sql_signature:
            st.write(f"**SQL Search Signature:** {sql_signature}")
        st.write("**Search Text:**")
        st.write(artifact.search_text or "")
        st.write("**Embedding Text:**")
        st.write(artifact.embedding_text or "")


def build_match_snippet(artifact, query: str) -> str:
    clean_query = query.strip()
    if not clean_query:
        return ""

    fields = [
        ("Name", artifact.name),
        ("Summary", artifact.summary),
        ("Search Text", artifact.search_text),
        ("Embedding Text", artifact.embedding_text),
        ("Components", artifact.component_types),
        ("File Path", artifact.file_path),
    ]

    for label, value in fields:
        text = str(value or "")
        match = re.search(re.escape(clean_query), text, flags=re.IGNORECASE)
        if not match:
            continue

        start = max(match.start() - 60, 0)
        end = min(match.end() + 100, len(text))
        prefix = "..." if start > 0 else ""
        suffix = "..." if end < len(text) else ""
        snippet = " ".join(text[start:end].split())
        return f"{label}: {prefix}{snippet}{suffix}"

    return ""


def build_match_evidence(artifact, query: str, filters: dict) -> list[str]:
    evidence = parse_json_object(artifact.evidence_json)
    reasons = []
    query_terms = normalize_query_terms(query)

    enabled_fields = get_enabled_match_evidence_fields(filters)
    for field in enabled_fields:
        if field["kind"] == "text":
            reasons.extend(
                match_text_field(
                    field["reason_label"],
                    field["getter"](artifact, evidence),
                    query_terms,
                )
            )
        elif field["kind"] == "list":
            reasons.extend(
                match_list_field(
                    field["reason_label"],
                    field["getter"](artifact, evidence),
                    query_terms,
                )
            )
        elif field["kind"] == "custom":
            reasons.extend(field["matcher"](artifact, evidence, query_terms))

    reasons.extend(match_filter_evidence(artifact, evidence, filters))

    return dedupe_keep_order(reasons)


def get_enabled_match_evidence_fields(filters: dict) -> list[dict]:
    selected_keys = (
        filters["evidence_fields"]
        if "evidence_fields" in filters
        else DEFAULT_MATCH_EVIDENCE_FIELDS
    )
    selected_key_set = set(selected_keys)
    return [field for field in MATCH_EVIDENCE_FIELDS if field["key"] in selected_key_set]


def normalize_query_terms(query: str) -> list[str]:
    clean = query.strip().lower()
    if not clean:
        return []
    compact = re.sub(r"[\s_-]+", "", clean)
    terms = [clean]
    if compact and compact != clean:
        terms.append(compact)
    return dedupe_keep_order(terms)


def match_text_field(label: str, value: str | None, query_terms: list[str]) -> list[str]:
    if not query_terms:
        return []
    text = str(value or "").lower()
    return [f"{label}: {value}" for term in query_terms if term and term in text][:1]


def match_list_field(label: str, values: list[str], query_terms: list[str]) -> list[str]:
    if not query_terms:
        return []
    matches = []
    for value in values:
        value_text = str(value)
        lower_value = value_text.lower()
        compact_value = re.sub(r"[\s_-]+", "", lower_value)
        if any(term in lower_value or term in compact_value for term in query_terms):
            matches.append(f"{label}: {value_text}")
    return matches[:3]


def match_dependency_evidence(evidence: dict, query_terms: list[str]) -> list[str]:
    matches = []
    for dep in evidence.get("job_dependencies") or []:
        target = dep.get("target_job") or dep.get("target_id") or ""
        component = dep.get("component") or "tRunJob"
        haystack = f"{target} {component}".lower()
        if any(term in haystack for term in query_terms):
            matches.append(f"dependency: {target}")
    return matches[:3]


def match_related_routine_evidence(evidence: dict, query_terms: list[str]) -> list[str]:
    matches = []
    for routine in evidence.get("related_routines") or []:
        values = [
            routine.get("name", ""),
            routine.get("summary", ""),
            *(routine.get("auth_signals") or []),
            *(routine.get("config_signals") or []),
            *(routine.get("code_keywords") or []),
            *(routine.get("matched_by") or []),
        ]
        haystack = " ".join(str(value) for value in values).lower()
        compact_haystack = re.sub(r"[\s_-]+", "", haystack)
        if any(term in haystack or term in compact_haystack for term in query_terms):
            matches.append(f"related routine: {routine.get('name', '')}")
    return matches[:3]


def match_vulnerability_scan_evidence(artifact, evidence: dict, query_terms: list[str]) -> list[str]:
    scan = evidence.get("vulnerability_scan") or {}
    values = []

    studio_info = scan.get("studio_patch_info") or evidence.get("studio_patch_info") or {}
    values.extend(studio_info.values())

    for vuln in get_artifact_vulnerabilities(artifact):
        values.extend(
            [
                vuln.get("package", ""),
                vuln.get("current_version", ""),
                vuln.get("vulnerability_id", ""),
                vuln.get("osv_id", ""),
                vuln.get("severity", ""),
                vuln.get("summary", ""),
                vuln.get("recommended_fix", ""),
                *(vuln.get("aliases") or []),
                *(vuln.get("fixed_versions") or []),
            ]
        )

    matches = []
    for value in values:
        text = str(value or "")
        lower_text = text.lower()
        compact_text = re.sub(r"[\s_-]+", "", lower_text)
        if any(term in lower_text or term in compact_text for term in query_terms):
            matches.append(f"vulnerability scan: {text}")

    return matches[:3]


def match_filter_evidence(artifact, evidence: dict, filters: dict) -> list[str]:
    reasons = []
    if filters.get("projects") and artifact.project_name in filters["projects"]:
        reasons.append(f"project filter: {artifact.project_name}")
    if filters.get("databases") and evidence.get("database_technology") in filters["databases"]:
        reasons.append(f"database filter: {evidence.get('database_technology')}")
    reasons.extend(match_selected_values("auth filter", evidence.get("auth_signals") or [], filters.get("auth_signals")))
    reasons.extend(match_selected_values("config filter", evidence.get("config_signals") or [], filters.get("config_signals")))
    reasons.extend(match_selected_values("component filter", evidence.get("components") or [], filters.get("components")))
    if filters.get("has_sql"):
        reasons.append("filter: has SQL")
    if filters.get("has_rest"):
        reasons.append("filter: has REST/API")
    if filters.get("has_secrets"):
        reasons.append("filter: has secrets/key material")
    if filters.get("has_dependencies"):
        reasons.append("filter: has tRunJob dependencies")
    return reasons


def match_selected_values(label: str, values: list[str], selected_values) -> list[str]:
    selected = set(selected_values or [])
    return [f"{label}: {value}" for value in values if value in selected][:3]


def render_job_flow_preview(artifact) -> None:
    if artifact.artifact_type != "job":
        return

    screenshot_path = find_job_screenshot_path(artifact.file_path)
    if not screenshot_path:
        return

    image_bytes = extract_screenshot_image(screenshot_path)
    if not image_bytes:
        return

    with st.expander("Job Flow Preview", expanded=True):
        st.image(image_bytes, caption=screenshot_path.name, use_container_width=True)


def find_job_screenshot_path(file_path: str | None) -> Path | None:
    if not file_path:
        return None

    item_path = Path(file_path)
    screenshot_path = item_path.with_suffix(".screenshot")
    if screenshot_path.exists():
        return screenshot_path
    return None


def extract_screenshot_image(screenshot_path: Path) -> bytes | None:
    try:
        root = ET.parse(screenshot_path).getroot()
    except Exception:
        return None


def render_artifact_blueprint(artifact) -> None:
    blueprint = build_artifact_blueprint(artifact)
    with st.expander("ETL Blueprint", expanded=True):
        st.caption("Implementation-neutral design generated from parsed Talend evidence.")

        overview_cols = st.columns(4)
        overview_cols[0].metric("Components", len(blueprint["components"]))
        overview_cols[1].metric("SQL Operations", len(blueprint["sql_operations"]))
        overview_cols[2].metric("Contexts", len(blueprint["contexts"]))
        overview_cols[3].metric("Dependencies", len(blueprint["dependencies"]))

        st.write("**Purpose:**")
        st.write(blueprint["purpose"])

        st.write("**Design Summary:**")
        st.dataframe(build_blueprint_summary_rows(blueprint), use_container_width=True, hide_index=True)

        tabs = st.tabs(["Sources / Targets", "Flow", "Config", "Blueprint YAML"])
        with tabs[0]:
            render_blueprint_list("Source tables", blueprint["source_tables"])
            render_blueprint_list("Target tables", blueprint["target_tables"])
            render_blueprint_list("Columns / fields", blueprint["fields"])
        with tabs[1]:
            render_blueprint_list("Components", blueprint["components"])
            render_blueprint_list("SQL operations", blueprint["sql_operations"])
            render_blueprint_list("Child jobs", blueprint["dependencies"])
        with tabs[2]:
            render_blueprint_list("Context variables", blueprint["contexts"])
            render_blueprint_list("Authentication signals", blueprint["auth_signals"])
            render_blueprint_list("Implementation notes", blueprint["implementation_notes"])
        with tabs[3]:
            yaml_text = format_blueprint_yaml(blueprint)
            st.code(yaml_text, language="yaml")
            st.download_button(
                "Download Blueprint YAML",
                data=yaml_text,
                file_name=f"{safe_filename(artifact.name)}_blueprint.yaml",
                mime="text/yaml",
            )


def build_artifact_blueprint(artifact) -> dict:
    evidence = parse_json_object(artifact.evidence_json)
    sql_items = evidence.get("sql") or []
    dependencies = evidence.get("job_dependencies") or parse_job_dependencies(artifact.job_dependencies)
    components = dedupe_keep_order(evidence.get("components") or split_component_text(artifact.component_types))
    source_tables = collect_blueprint_tables(sql_items, source=True)
    target_tables = collect_blueprint_tables(sql_items, source=False)
    all_tables = dedupe_keep_order(source_tables + target_tables)
    fields = collect_blueprint_fields(evidence, sql_items)

    return {
        "job_name": artifact.name,
        "artifact_type": artifact.artifact_type,
        "project": artifact.project_name or "",
        "repo": artifact.repo_name,
        "purpose": infer_blueprint_purpose(artifact, evidence, source_tables, target_tables),
        "pattern": infer_blueprint_pattern(components, sql_items, dependencies),
        "source_tables": source_tables or all_tables,
        "target_tables": target_tables,
        "fields": fields,
        "components": components[:30],
        "sql_operations": format_blueprint_sql_operations(sql_items),
        "contexts": dedupe_keep_order(evidence.get("context_refs") or [])[:30],
        "auth_signals": dedupe_keep_order(evidence.get("auth_signals") or [])[:20],
        "config_signals": dedupe_keep_order(evidence.get("config_signals") or [])[:20],
        "dependencies": format_blueprint_dependencies(dependencies),
        "implementation_notes": build_blueprint_notes(evidence, sql_items, dependencies),
    }


def build_blueprint_summary_rows(blueprint: dict) -> list[dict]:
    return [
        {"Area": "Pattern", "Value": blueprint["pattern"]},
        {"Area": "Sources", "Value": join_or_dash(blueprint["source_tables"][:8])},
        {"Area": "Targets", "Value": join_or_dash(blueprint["target_tables"][:8])},
        {"Area": "Key fields", "Value": join_or_dash(blueprint["fields"][:12])},
        {"Area": "Config signals", "Value": join_or_dash(blueprint["config_signals"][:8])},
    ]


def render_blueprint_list(label: str, values: list[str]) -> None:
    st.write(f"**{label}:**")
    if not values:
        st.caption("None detected from current evidence.")
        return
    for value in values[:30]:
        st.write(f"- `{value}`")


def collect_blueprint_tables(sql_items: list[dict], source: bool) -> list[str]:
    source_ops = {"SELECT", "WITH", "UNKNOWN", ""}
    target_ops = {"INSERT", "UPDATE", "DELETE", "MERGE", "CREATE"}
    tables = []
    for item in sql_items:
        operation = str(item.get("operation") or "").upper()
        if source and operation in source_ops:
            tables.extend(item.get("tables") or [])
        elif not source and operation in target_ops:
            tables.extend(item.get("tables") or [])
    return dedupe_keep_order([table for table in tables if table])


def collect_blueprint_fields(evidence: dict, sql_items: list[dict]) -> list[str]:
    fields = []
    for item in sql_items:
        fields.extend(item.get("columns") or [])
    fields.extend(evidence.get("context_refs") or [])
    return dedupe_keep_order(
        [
            field
            for field in fields
            if field
            and not is_noisy_catalog_field(field)
            and not is_sql_keyword_catalog_field(field)
        ]
    )[:40]


def format_blueprint_sql_operations(sql_items: list[dict]) -> list[str]:
    operations = []
    for item in sql_items[:20]:
        operation = item.get("operation") or "SQL"
        tables = ", ".join(item.get("tables") or [])
        signature = item.get("signature") or ""
        label = operation
        if tables:
            label += f" on {tables}"
        if signature:
            label += f": {signature[:140]}"
        operations.append(label)
    return operations


def format_blueprint_dependencies(dependencies: list[dict]) -> list[str]:
    labels = []
    for dep in dependencies:
        target = dep.get("target_job") or dep.get("target_id") or "unknown job"
        component = dep.get("component") or "tRunJob"
        labels.append(f"{component} -> {target}")
    return labels[:20]


def infer_blueprint_purpose(artifact, evidence: dict, source_tables: list[str], target_tables: list[str]) -> str:
    if artifact.summary:
        return artifact.summary
    if source_tables and target_tables:
        return f"Move or transform data from {join_or_dash(source_tables[:3])} to {join_or_dash(target_tables[:3])}."
    if source_tables:
        return f"Read and process data from {join_or_dash(source_tables[:3])}."
    if evidence.get("urls"):
        return f"Integrate with endpoint(s): {join_or_dash(evidence['urls'][:2])}."
    return "Talend workflow derived from parsed job evidence."


def infer_blueprint_pattern(components: list[str], sql_items: list[dict], dependencies: list[dict]) -> str:
    component_text = " ".join(components).lower()
    sql_ops = {str(item.get("operation") or "").upper() for item in sql_items}
    if dependencies:
        return "job orchestration"
    if "tmap" in component_text and {"SELECT", "INSERT"} & sql_ops:
        return "database transform/load"
    if "fileinput" in component_text and "dboutput" in component_text:
        return "file to database load"
    if "dbinput" in component_text and "fileoutput" in component_text:
        return "database export"
    if "rest" in component_text or "http" in component_text:
        return "API integration"
    if sql_items:
        return "SQL-driven data processing"
    return "Talend component workflow"


def build_blueprint_notes(evidence: dict, sql_items: list[dict], dependencies: list[dict]) -> list[str]:
    notes = []
    if evidence.get("database_technology"):
        notes.append(f"Database technology detected: {evidence['database_technology']}")
    if evidence.get("auth_signals"):
        notes.append("Review authentication and secret handling before implementation.")
    if dependencies:
        notes.append("Preserve child-job orchestration or replace it with workflow dependencies.")
    if sql_items:
        notes.append("Validate SQL syntax, table names, and column mappings in the target runtime.")
    if evidence.get("context_refs"):
        notes.append("Parameterize environment-specific values using context/config variables.")
    return notes or ["Review component configuration and schemas before implementation."]


def format_blueprint_yaml(blueprint: dict) -> str:
    lines = []
    for key in [
        "job_name",
        "artifact_type",
        "project",
        "repo",
        "purpose",
        "pattern",
        "source_tables",
        "target_tables",
        "fields",
        "components",
        "sql_operations",
        "contexts",
        "auth_signals",
        "config_signals",
        "dependencies",
        "implementation_notes",
    ]:
        append_yaml_value(lines, key, blueprint.get(key))
    return "\n".join(lines) + "\n"


def append_yaml_value(lines: list[str], key: str, value) -> None:
    if isinstance(value, list):
        lines.append(f"{key}:")
        if not value:
            lines.append("  []")
            return
        for item in value:
            lines.append(f"  - {yaml_scalar(item)}")
        return
    lines.append(f"{key}: {yaml_scalar(value)}")


def yaml_scalar(value) -> str:
    text = str(value or "")
    escaped = text.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def join_or_dash(values: list[str]) -> str:
    return ", ".join(values) if values else "-"


def safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", str(value or "artifact")).strip("_") or "artifact"

    encoded = root.attrib.get("value", "").strip()
    if not encoded:
        return None

    try:
        return base64.b64decode(encoded)
    except Exception:
        return None


def format_summary_status(value: str | None) -> str:
    status = str(value or "").strip()
    if status.startswith("complete:"):
        return "complete"
    return status


def merge_artifact_results(primary, secondary):
    seen = set()
    merged = []
    for artifact in list(primary) + list(secondary):
        if artifact.id in seen:
            continue
        seen.add(artifact.id)
        merged.append(artifact)
    return merged


def load_regeneration_stats() -> dict:
    with SessionLocal() as db:
        artifacts = get_all_artifacts(db)

    current_summary_status = build_current_summary_status()
    current_embedding_model = get_current_embedding_model_identifier()
    stats = {
        "total": len(artifacts),
        "jobs": 0,
        "routines": 0,
        "joblets": 0,
        "summarized": 0,
        "missing_summaries": 0,
        "failed_summaries": 0,
        "pending_summaries": 0,
        "stale_summaries": 0,
        "embedded": 0,
        "missing_embeddings": 0,
        "stale_embeddings": 0,
    }

    for artifact in artifacts:
        summary_applicable = artifact.artifact_type in {"job", "routine"}
        if artifact.artifact_type == "job":
            stats["jobs"] += 1
        elif artifact.artifact_type == "routine":
            stats["routines"] += 1
        elif artifact.artifact_type == "joblet":
            stats["joblets"] += 1

        has_summary_text = bool(str(artifact.summary or "").strip())
        is_complete = str(artifact.summary_status or "").startswith("complete:")
        if summary_applicable and has_summary_text and is_complete:
            stats["summarized"] += 1
        if summary_applicable and not has_summary_text:
            stats["missing_summaries"] += 1
        if summary_applicable and str(artifact.summary_status or "").lower().startswith("failed"):
            stats["failed_summaries"] += 1
        if summary_applicable and str(artifact.summary_status or "").lower() == "pending":
            stats["pending_summaries"] += 1
        if summary_applicable and has_summary_text and artifact.summary_status != current_summary_status:
            stats["stale_summaries"] += 1

        if has_summary_text:
            source_hash = build_embedding_source_hash(build_semantic_document(artifact))
            embedding_current = (
                artifact.embedding_vector is not None
                and artifact.embedding_hash == source_hash
                and artifact.embedding_model == current_embedding_model
            )
            if embedding_current:
                stats["embedded"] += 1
            elif artifact.embedding_vector is None:
                stats["missing_embeddings"] += 1
            else:
                stats["stale_embeddings"] += 1

    return stats


def get_current_embedding_model_identifier() -> str:
    if get_embedding_provider() == "openai":
        return get_openai_embedding_model_identifier()
    return get_sentence_transformer_model_name()


def render_regeneration_dashboard() -> None:
    stats = load_regeneration_stats()
    st.sidebar.header("Regeneration")
    col1, col2 = st.sidebar.columns(2)
    col1.metric("Artifacts", stats["total"])
    col2.metric("Embedded", stats["embedded"])
    col1.metric("Summarized", stats["summarized"])
    col2.metric("Missing Emb.", stats["missing_embeddings"])

    with st.sidebar.expander("Regeneration Details"):
        st.write(f"**Jobs:** {stats['jobs']}")
        st.write(f"**Routines:** {stats['routines']}")
        st.write(f"**Joblets:** {stats['joblets']}")
        st.write(f"**Missing summaries:** {stats['missing_summaries']}")
        st.write(f"**Stale summaries:** {stats['stale_summaries']}")
        st.write(f"**Pending summaries:** {stats['pending_summaries']}")
        st.write(f"**Failed summaries:** {stats['failed_summaries']}")
        st.write(f"**Stale embeddings:** {stats['stale_embeddings']}")


def render_search_controls() -> tuple[str, str, str]:
    st.subheader("Search")
    query = st.text_input(
        "Search artifacts",
        placeholder="Try HashiCorp Vault, Snowflake JWT, SSH, Salesforce, table names...",
        label_visibility="collapsed",
    )
    scope_col, mode_col = st.columns([1.2, 1])
    artifact_type = scope_col.selectbox(
        "Scope",
        ["All", "Jobs", "Routines", "Joblets"],
    )
    search_mode = mode_col.radio(
        "Mode",
        ["Semantic", "Text"],
        horizontal=True,
        index=0,
    )
    return query, artifact_type, search_mode


def render_maintenance_actions(artifact_type: str) -> None:
    st.sidebar.header("Repository Maintenance")
    with st.sidebar.expander("Run actions", expanded=False):
        if st.button("Scan Local Repositories", use_container_width=True):
            try:
                artifacts = scan_repositories()

                if not artifacts:
                    st.warning("No artifacts found in data/repos/")
                else:
                    with SessionLocal() as db:
                        inserted, updated, skipped_unchanged = insert_artifacts(db, artifacts)

                    st.success(
                        "Scan complete. "
                        f"Inserted: {inserted}, Updated: {updated}, Unchanged: {skipped_unchanged}"
                    )

            except Exception as e:
                st.error(f"Scan failed: {e}")

        if st.button("Generate Summaries", use_container_width=True):
            try:
                processed, skipped_unchanged, failed = summarize_all_artifacts()
                st.success(
                    "Summaries generated. "
                    f"Processed: {processed}, Skipped unchanged: {skipped_unchanged}, Failed: {failed}"
                )
            except Exception as e:
                st.error(f"Summary generation failed: {e}")

        if st.button("Build Embeddings", use_container_width=True):
            try:
                considered, updated = build_missing_embeddings(artifact_type=artifact_type)
                st.success(
                    f"Embeddings ready. Considered: {considered}, Created/updated: {updated}"
                )
            except Exception as e:
                st.error(f"Embedding build failed: {e}")
                st.info(
                    "For the first model download, run this from the same activated virtualenv: "
                    "python .\\scripts\\build_embeddings.py"
                )

    with st.sidebar.expander("Developer tools", expanded=False):
        if st.button("Load Sample Data", use_container_width=True):
            try:
                with SessionLocal() as db:
                    create_sample_artifacts(db)
                st.success("Sample artifacts loaded.")
            except Exception as e:
                st.error(f"Loading sample data failed: {e}")


def render_export_actions() -> None:
    st.sidebar.header("Export")
    with st.sidebar.expander("Artifact inventory", expanded=False):
        with SessionLocal() as db:
            artifacts = get_all_artifacts(db)

        rows = build_export_rows(artifacts)
        st.caption(f"{len(rows)} artifact(s)")
        st.download_button(
            "Download CSV",
            data=build_csv_export(rows),
            file_name="talend_artifact_inventory.csv",
            mime="text/csv",
            use_container_width=True,
            disabled=not rows,
        )

        if st.checkbox("Preview inventory"):
            st.dataframe(rows[:200], use_container_width=True, hide_index=True)


def build_export_rows(artifacts) -> list[dict]:
    rows = []
    for artifact in artifacts:
        evidence = parse_json_object(artifact.evidence_json)
        rows.append(
            {
                "name": artifact.name,
                "type": artifact.artifact_type,
                "project": artifact.project_name or "",
                "repo": artifact.repo_name,
                "file_path": artifact.file_path,
                "summary": artifact.summary or "",
                "flow": evidence.get("flow") or "",
                "database": evidence.get("database_technology") or "",
                "auth_signals": ", ".join(evidence.get("auth_signals") or []),
                "config_signals": ", ".join(evidence.get("config_signals") or []),
                "context_refs": ", ".join(evidence.get("context_refs") or []),
                "urls": ", ".join(evidence.get("urls") or []),
                "sql_tables": ", ".join(extract_sql_tables_for_export(evidence)),
                "components": artifact.component_types or "",
                "job_dependencies": format_job_dependencies_for_export(evidence),
                "related_routines": format_related_routines_for_export(evidence),
                "studio_patch": format_studio_patch_for_export(evidence),
                "vulnerabilities": format_vulnerabilities_for_artifact(artifact),
            }
        )
    return rows


def build_vulnerability_export_rows() -> list[dict]:
    rows = []
    with SessionLocal() as db:
        findings = get_all_vulnerability_findings(db)

    for finding in findings:
        vuln = finding_to_dict(finding)
        rows.append(
            {
                "project": finding.project_name or "",
                "repo": finding.repo_name,
                "artifact_name": finding.artifact_name,
                "artifact_type": finding.artifact_type,
                "file_path": finding.file_path,
                "input_type": finding.input_type,
                "studio_version": finding.studio_display_version or finding.studio_version or "",
                "studio_patch": finding.studio_patch or "",
                "package": vuln.get("package") or "",
                "current_version": vuln.get("current_version") or "",
                "severity": vuln.get("severity") or "",
                "issue": vuln.get("vulnerability_id") or vuln.get("osv_id") or "",
                "osv_id": vuln.get("osv_id") or "",
                "aliases": ", ".join(vuln.get("aliases") or []),
                "fixed_versions": ", ".join(vuln.get("fixed_versions") or []),
                "recommended_fix": vuln.get("recommended_fix") or "",
                "summary": vuln.get("summary") or "",
                "source_pom": finding.source_pom or "",
                "source_jar": finding.source_jar or "",
                "references": ", ".join(vuln.get("references") or []),
            }
            )
    return rows


def extract_sql_tables_for_export(evidence: dict) -> list[str]:
    tables = []
    for item in evidence.get("sql") or []:
        tables.extend(item.get("tables") or [])
    return dedupe_keep_order(tables)


def format_job_dependencies_for_export(evidence: dict) -> str:
    dependencies = []
    for dep in evidence.get("job_dependencies") or []:
        target = dep.get("target_job") or dep.get("target_id") or ""
        if target:
            dependencies.append(target)
    return ", ".join(dedupe_keep_order(dependencies))


def format_related_routines_for_export(evidence: dict) -> str:
    routines = [
        routine.get("name", "")
        for routine in evidence.get("related_routines") or []
        if routine.get("name")
    ]
    return ", ".join(dedupe_keep_order(routines))


def format_studio_patch_for_export(evidence: dict) -> str:
    info = evidence.get("studio_patch_info") or {}
    parts = [
        info.get("display_version") or info.get("version") or "",
        info.get("patch") or "",
    ]
    return " | ".join(part for part in parts if part)


def format_vulnerabilities_for_artifact(artifact) -> str:
    vulnerabilities = []
    for vuln in get_artifact_vulnerabilities(artifact):
        package = vuln.get("package") or ""
        current_version = vuln.get("current_version") or ""
        issue = vuln.get("vulnerability_id") or vuln.get("osv_id") or ""
        fix = vuln.get("recommended_fix") or ""
        if package:
            vulnerabilities.append(f"{package}:{current_version} {issue} {fix}".strip())
    return " | ".join(vulnerabilities)


def build_csv_export(rows: list[dict]) -> str:
    if not rows:
        return ""

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def load_filter_options() -> dict:
    with SessionLocal() as db:
        artifacts = get_all_artifacts(db)

    options = {
        "projects": set(),
        "databases": set(),
        "auth_signals": set(),
        "config_signals": set(),
        "components": set(),
    }

    for artifact in artifacts:
        if artifact.project_name:
            options["projects"].add(artifact.project_name)

        evidence = parse_json_object(artifact.evidence_json)
        if evidence.get("database_technology"):
            options["databases"].add(evidence["database_technology"])
        options["auth_signals"].update(evidence.get("auth_signals") or [])
        options["config_signals"].update(evidence.get("config_signals") or [])
        options["components"].update(evidence.get("components") or [])

        for component in split_component_text(artifact.component_types):
            options["components"].add(component)

    return {key: sorted(values) for key, values in options.items()}


def split_component_text(value: str | None) -> list[str]:
    return [part.strip() for part in str(value or "").split(",") if part.strip()]


def render_sidebar_filters() -> dict:
    options = load_filter_options()
    st.sidebar.header("Filters")
    evidence_label_by_key = {
        field["key"]: field["label"]
        for field in MATCH_EVIDENCE_FIELDS
    }
    selected_evidence_labels = st.sidebar.multiselect(
        "Why matched evidence",
        [field["label"] for field in MATCH_EVIDENCE_FIELDS],
        default=[
            evidence_label_by_key[key]
            for key in DEFAULT_MATCH_EVIDENCE_FIELDS
            if key in evidence_label_by_key
        ],
    )
    evidence_key_by_label = {
        field["label"]: field["key"]
        for field in MATCH_EVIDENCE_FIELDS
    }
    return {
        "projects": st.sidebar.multiselect("Project", options["projects"]),
        "databases": st.sidebar.multiselect("Database", options["databases"]),
        "auth_signals": st.sidebar.multiselect("Authentication", options["auth_signals"]),
        "config_signals": st.sidebar.multiselect("Config / Function", options["config_signals"]),
        "components": st.sidebar.multiselect("Component", options["components"]),
        "has_sql": st.sidebar.checkbox("Has SQL"),
        "has_rest": st.sidebar.checkbox("Has REST/API"),
        "has_secrets": st.sidebar.checkbox("Has secrets/key material"),
        "has_dependencies": st.sidebar.checkbox("Has tRunJob dependencies"),
        "evidence_fields": [
            evidence_key_by_label[label]
            for label in selected_evidence_labels
            if label in evidence_key_by_label
        ],
    }


def reset_detail_view_when_search_changes(
    query: str,
    artifact_type: str,
    search_mode: str,
    filters: dict,
) -> None:
    signature = json.dumps(
        {
            "query": query,
            "artifact_type": artifact_type,
            "search_mode": search_mode,
            "filters": filters,
        },
        sort_keys=True,
        default=str,
    )
    previous_signature = st.session_state.get("search_signature")
    if previous_signature is not None and previous_signature != signature:
        st.session_state["selected_artifact_id"] = None
    st.session_state["search_signature"] = signature


def apply_artifact_filters(artifacts, filters: dict):
    return [
        artifact
        for artifact in artifacts
        if artifact_matches_filters(artifact, filters)
    ]


def artifact_matches_filters(artifact, filters: dict) -> bool:
    evidence = parse_json_object(artifact.evidence_json)

    if filters["projects"] and artifact.project_name not in filters["projects"]:
        return False
    if filters["databases"] and evidence.get("database_technology") not in filters["databases"]:
        return False

    auth_signals = set(evidence.get("auth_signals") or [])
    if filters["auth_signals"] and not auth_signals.intersection(filters["auth_signals"]):
        return False

    config_signals = set(evidence.get("config_signals") or [])
    if filters["config_signals"] and not config_signals.intersection(filters["config_signals"]):
        return False

    components = set(evidence.get("components") or split_component_text(artifact.component_types))
    if filters["components"] and not components.intersection(filters["components"]):
        return False

    sql_items = evidence.get("sql") or []
    if filters["has_sql"] and not sql_items:
        return False

    signal_blob = " ".join(
        str(value)
        for value in (
            list(config_signals)
            + list(auth_signals)
            + list(components)
            + [artifact.search_text or "", artifact.embedding_text or ""]
        )
    ).lower()
    if filters["has_rest"] and not any(token in signal_blob for token in ["rest", "api", "http"]):
        return False
    if filters["has_secrets"] and not any(
        token in signal_blob
        for token in ["secret", "token", "password", "private key", "key-pair", "vault"]
    ):
        return False

    dependencies = evidence.get("job_dependencies") or parse_job_dependencies(artifact.job_dependencies)
    if filters["has_dependencies"] and not dependencies:
        return False

    return True


def render_job_dependencies(artifact) -> None:
    dependencies = parse_job_dependencies(artifact.job_dependencies)
    with SessionLocal() as db:
        hierarchy = collect_dependency_hierarchy(db, artifact)

    if not dependencies and not hierarchy["parents"] and not hierarchy["children"]:
        return

    st.write("**Job Dependencies:**")
    if hierarchy["parents"]:
        st.write("**Parent jobs:**")
        for parent in hierarchy["parents"]:
            st.write(
                f"- `{parent['source']}` calls this job through `{parent['component']}`"
            )

    if dependencies:
        st.write("**Child jobs:**")
        for dep, target in hierarchy["direct_children"]:
            target_label = dep.get("target_job") or dep.get("target_id") or "unknown job"
            details = []
            if dep.get("component"):
                details.append(dep["component"])
            if dep.get("context"):
                details.append(f"context {dep['context']}")
            if dep.get("version"):
                details.append(f"version {dep['version']}")
            if dep.get("independent_process") == "true":
                details.append("independent process")
            status = "resolved" if target else "unresolved"
            st.write(f"- runs `{target_label}` ({status}; {', '.join(details)})")

    st.graphviz_chart(build_dependency_graph_dot(artifact, hierarchy["edges"]))


def render_artifact_evidence(artifact) -> None:
    evidence = parse_json_object(artifact.evidence_json)
    if not evidence:
        return

    with st.expander("Evidence", expanded=True):
        cols = st.columns(3)
        cols[0].metric("Components", len(evidence.get("components") or []))
        cols[1].metric("SQL Items", len(evidence.get("sql") or []))
        cols[2].metric("Dependencies", len(evidence.get("job_dependencies") or []))

        overview_tab, connectivity_tab, sql_tab, code_tab, vuln_tab = st.tabs(
            ["Overview", "Connectivity", "SQL / Data", "Routine / Code", "Vulnerability Scan"]
        )

        with overview_tab:
            if evidence.get("flow"):
                st.write(f"**Flow:** {evidence['flow']}")
            render_evidence_list("Components", evidence.get("components"))
            render_evidence_list("Config / Function Signals", evidence.get("config_signals"))

        with connectivity_tab:
            if evidence.get("database_technology"):
                st.write(f"**Database:** {evidence['database_technology']}")
            render_evidence_list("Authentication Signals", evidence.get("auth_signals"))
            render_evidence_list("Context References", evidence.get("context_refs"))
            render_evidence_list("URLs / Endpoints", evidence.get("urls"))

        with sql_tab:
            render_sql_evidence(evidence.get("sql") or [])

        with code_tab:
            render_related_routines(evidence.get("related_routines") or [])
            render_routine_evidence(evidence.get("routine") or {})
            render_evidence_list("Code Keywords", evidence.get("code_keywords"))

        with vuln_tab:
            render_vulnerability_scan(artifact, evidence)


def render_evidence_list(label: str, values) -> None:
    values = [str(value) for value in values or [] if value]
    if values:
        st.write(f"**{label}:** {', '.join(values[:20])}")
    else:
        st.caption(f"No {label.lower()} detected.")


def render_sql_evidence(sql_items: list[dict]) -> None:
    if not sql_items:
        st.caption("No SQL evidence detected.")
        return

    for item in sql_items[:8]:
        tables = ", ".join(item.get("tables") or [])
        op = item.get("operation") or "SQL"
        signature = item.get("signature") or ""
        label = f"{op}"
        if tables:
            label += f" on {tables}"
        st.write(f"- {label}: `{signature[:180]}`")


def render_vulnerability_scan(artifact, evidence: dict) -> None:
    scan = evidence.get("vulnerability_scan") or {}
    studio_info = evidence.get("studio_patch_info") or scan.get("studio_patch_info") or {}

    if studio_info:
        st.write("**Studio / Patch Info:**")
        if studio_info.get("display_version"):
            st.write(f"- Display version: `{studio_info['display_version']}`")
        if studio_info.get("version"):
            st.write(f"- Version: `{studio_info['version']}`")
        if studio_info.get("patch"):
            st.write(f"- Patch: `{studio_info['patch']}`")
        if studio_info.get("source_path"):
            st.caption(f"Source: {studio_info['source_path']}")
    else:
        st.caption("No Studio / patch info detected.")

    if not scan:
        st.caption("Vulnerability scan has not been run for this artifact.")
        return

    if scan.get("status") == "not_available":
        st.caption("No poms folder found for this project, so jar vulnerability evidence is not available.")
        return

    st.write(f"**POM dependency count for this artifact:** {scan.get('job_dependency_count', 0)}")
    vulnerabilities = get_artifact_vulnerabilities(artifact)
    if not vulnerabilities:
        st.success("No vulnerable Maven dependencies detected for this artifact.")
        return

    st.write("**Vulnerable Jars:**")
    rows = []
    for vuln in vulnerabilities:
        rows.append(
            {
                "Jar": f"{vuln.get('package', '')}:{vuln.get('current_version', '')}",
                "Severity": vuln.get("severity") or "",
                "Issue": vuln.get("vulnerability_id") or vuln.get("osv_id") or "",
                "Fix": vuln.get("recommended_fix") or "",
            }
        )
    st.dataframe(rows, use_container_width=True, hide_index=True)

    for vuln in vulnerabilities[:8]:
        label = vuln.get("vulnerability_id") or vuln.get("osv_id") or "vulnerability"
        package = vuln.get("package") or ""
        version = vuln.get("current_version") or ""
        with st.expander(f"{label} - {package}:{version}", expanded=False):
            if vuln.get("summary"):
                st.write(vuln["summary"])
            if vuln.get("fixed_versions"):
                st.write("**Fixed versions:** " + ", ".join(vuln["fixed_versions"]))
            if vuln.get("recommended_fix"):
                st.write("**Recommended fix:** " + vuln["recommended_fix"])
            render_evidence_list("References", vuln.get("references"))


def render_routine_evidence(routine: dict) -> None:
    if not any(routine.values()):
        st.caption("No routine/class evidence detected.")
        return

    render_evidence_list("Classes", routine.get("classes"))
    render_evidence_list("Methods", routine.get("methods"))
    render_evidence_list("Parameters", routine.get("parameters"))
    render_evidence_list("Referenced Classes", routine.get("qualified_refs"))


def render_related_routines(related_routines: list[dict]) -> None:
    if not related_routines:
        st.caption("No related routines detected.")
        return

    st.write("**Related Routines:**")
    for routine in related_routines[:10]:
        name = routine.get("name") or "unknown routine"
        signals = (
            (routine.get("auth_signals") or [])
            + (routine.get("config_signals") or [])
            + (routine.get("code_keywords") or [])
        )
        details = []
        if signals:
            details.append(format_plain_list(dedupe_keep_order(signals)[:6]))
        if routine.get("matched_by"):
            details.append("matched by " + format_plain_list(routine["matched_by"][:4]))
        detail_text = f" ({'; '.join(details)})" if details else ""
        st.write(f"- `{name}`{detail_text}")
        if routine.get("summary"):
            st.caption(routine["summary"][:300])


def format_plain_list(values: list[str]) -> str:
    values = [str(value) for value in values if value]
    if not values:
        return ""
    if len(values) == 1:
        return values[0]
    if len(values) == 2:
        return f"{values[0]} and {values[1]}"
    return ", ".join(values[:-1]) + f", and {values[-1]}"


def dedupe_keep_order(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def parse_json_object(raw_value: str | None) -> dict:
    if not raw_value:
        return {}
    try:
        value = json.loads(raw_value)
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}


def resolve_dependencies(db, artifact, dependencies: list[dict]):
    return [
        (
            dep,
            find_artifact_by_job_name(
                db=db,
                repo_name=artifact.repo_name,
                project_name=artifact.project_name,
                job_name=dep.get("target_job", ""),
            ),
        )
        for dep in dependencies
    ]


def collect_dependency_hierarchy(db, artifact, max_depth: int = 3) -> dict:
    all_artifacts = get_all_artifacts(db)
    direct_children = resolve_dependencies(
        db,
        artifact,
        parse_job_dependencies(artifact.job_dependencies),
    )
    child_edges = collect_child_dependency_edges(db, artifact, max_depth=max_depth)
    parent_edges = collect_parent_dependency_edges(
        artifact,
        all_artifacts,
        max_depth=max_depth,
    )

    return {
        "direct_children": direct_children,
        "parents": [
            edge for edge in parent_edges if edge["target"] == artifact.name
        ],
        "children": [
            edge for edge in child_edges if edge["source"] == artifact.name
        ],
        "edges": dedupe_graph_edges(parent_edges + child_edges),
    }


def collect_child_dependency_edges(db, artifact, max_depth: int = 3):
    edges = []
    visited = set()

    def visit(current_artifact, depth: int) -> None:
        if depth > max_depth or current_artifact.id in visited:
            return
        visited.add(current_artifact.id)

        deps = parse_job_dependencies(current_artifact.job_dependencies)
        for dep, target in resolve_dependencies(db, current_artifact, deps):
            target_label = (
                target.name
                if target
                else dep.get("target_job") or dep.get("target_id") or "unknown job"
            )
            edges.append(
                {
                    "source": current_artifact.name,
                    "target": target_label,
                    "component": dep.get("component") or "tRunJob",
                    "resolved": bool(target),
                }
            )
            if target:
                visit(target, depth + 1)

    visit(artifact, 0)
    return edges


def collect_parent_dependency_edges(artifact, all_artifacts, max_depth: int = 3):
    edges = []
    visited = set()

    def visit(current_artifact, depth: int) -> None:
        if depth > max_depth or current_artifact.id in visited:
            return
        visited.add(current_artifact.id)

        parents = find_parent_artifacts(current_artifact, all_artifacts)
        for parent, dep in parents:
            edges.append(
                {
                    "source": parent.name,
                    "target": current_artifact.name,
                    "component": dep.get("component") or "tRunJob",
                    "resolved": True,
                }
            )
            visit(parent, depth + 1)

    visit(artifact, 0)
    return edges


def find_parent_artifacts(target_artifact, all_artifacts):
    parents = []
    for candidate in all_artifacts:
        if candidate.id == target_artifact.id or candidate.artifact_type != "job":
            continue
        for dep in parse_job_dependencies(candidate.job_dependencies):
            if dependency_targets_artifact(dep, target_artifact):
                parents.append((candidate, dep))
    return parents


def dependency_targets_artifact(dep: dict, artifact) -> bool:
    target_job = str(dep.get("target_job") or "").strip().lower()
    target_id = str(dep.get("target_id") or "").strip()
    artifact_base = artifact.name.rsplit("_", 1)[0].lower()

    if target_job and target_job in {artifact.name.lower(), artifact_base}:
        return True
    if target_job and artifact.name.lower().startswith(f"{target_job}_"):
        return True
    return bool(target_id and target_id in str(artifact.file_path))


def dedupe_graph_edges(edges: list[dict]) -> list[dict]:
    seen = set()
    result = []
    for edge in edges:
        key = (edge["source"], edge["target"], edge["component"])
        if key in seen:
            continue
        seen.add(key)
        result.append(edge)
    return result


def parse_job_dependencies(raw_value: str | None) -> list[dict]:
    if not raw_value:
        return []
    try:
        value = json.loads(raw_value)
    except Exception:
        return []
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def build_dependency_graph_dot(artifact, graph_edges) -> str:
    lines = [
        "digraph dependencies {",
        "rankdir=TB;",
        'node [shape=box, style="rounded,filled", fillcolor="#f8fafc", color="#111827"];',
        f'"{escape_dot(artifact.name)}" [fillcolor="#dcfce7", color="#166534"];',
    ]

    for edge in graph_edges:
        if not edge["resolved"]:
            lines.append(
                f'"{escape_dot(edge["target"])}" [fillcolor="#f0fdf4", color="#166534"];'
            )
        lines.append(
            f'"{escape_dot(edge["source"])}" -> "{escape_dot(edge["target"])}" '
            f'[label="{escape_dot(edge["component"])}"];'
        )

    lines.append("}")
    return "\n".join(lines)


def escape_dot(value: str) -> str:
    return str(value or "").replace("\\", "\\\\").replace('"', '\\"')


def render_kb_page() -> None:
    query, artifact_type, search_mode = render_search_controls()
    render_regeneration_dashboard()
    render_maintenance_actions(artifact_type)
    render_export_actions()
    filters = render_sidebar_filters()
    reset_detail_view_when_search_changes(query, artifact_type, search_mode, filters)
    st.divider()

    selected_artifact_id = st.session_state.get("selected_artifact_id")
    if selected_artifact_id:
        try:
            with SessionLocal() as db:
                selected_artifact = get_artifact_by_id(db, selected_artifact_id)
            if selected_artifact:
                render_artifact_detail(selected_artifact)
            else:
                st.session_state["selected_artifact_id"] = None
                st.warning("Selected artifact no longer exists.")
        except Exception as e:
            st.error(f"Failed to load artifact detail: {e}")
        return

    if query.strip() or artifact_type != "All":
        try:
            with SessionLocal() as db:
                candidates = search_artifacts(
                    db,
                    query="" if search_mode == "Semantic" else query,
                    artifact_type=artifact_type,
                )

            scores = {}
            if search_mode == "Semantic" and query.strip():
                semantic_results = semantic_search_artifacts_pgvector(
                    query=query,
                    artifact_type=artifact_type,
                )
                if semantic_results is None:
                    semantic_results = semantic_search_artifacts(candidates, query=query)
                artifacts = [result.artifact for result in semantic_results]
                scores = {result.artifact.id: result.score for result in semantic_results}
                if query.strip():
                    with SessionLocal() as db:
                        text_matches = search_artifacts(
                            db,
                            query=query,
                            artifact_type=artifact_type,
                        )
                    artifacts = merge_artifact_results(text_matches, artifacts)
            else:
                artifacts = candidates
            artifacts = apply_artifact_filters(artifacts, filters)

            st.subheader("Search Results")
            st.caption(f"{len(artifacts)} artifact(s) after filters")
            render_artifacts(artifacts, query=query, filters=filters, scores=scores)
        except Exception as e:
            st.error(f"Search failed: {e}")
    else:
        st.info("Search for an artifact, table, system, auth method, or technical signal.")


def render_catalog_page() -> None:
    st.subheader("Data Catalog")
    st.caption("Search field, column, SQL, context, and PII-style semantic evidence from Talend jobs.")

    action_col, export_col = st.columns([1, 1])
    with action_col:
        if st.button("Run Catalog Scan", use_container_width=True):
            try:
                stats = run_data_catalog_scan()
                st.success(
                    "Catalog scan complete. "
                    f"Processed: {stats['processed']}, "
                    f"Skipped unchanged: {stats['skipped_unchanged']}, "
                    f"Findings: {stats['findings']}, "
                    f"Failed: {stats['failed']}"
                )
            except Exception as e:
                st.error(f"Catalog scan failed: {e}")

    with SessionLocal() as db:
        all_findings = get_catalog_findings(db)
        options = get_catalog_filter_options(db)

    with export_col:
        export_rows = [catalog_finding_to_dict(finding) for finding in all_findings]
        st.download_button(
            "Download Catalog CSV",
            data=build_csv_export(export_rows),
            file_name="talend_data_catalog.csv",
            mime="text/csv",
            use_container_width=True,
            disabled=not export_rows,
        )

    query = st.text_input(
        "Catalog search",
        placeholder="Try ssn, social security number, email, dob, customer id, table name...",
    )
    filter_cols = st.columns(5)
    project = filter_cols[0].selectbox("Project", [""] + options["projects"], format_func=lambda value: value or "All")
    pii_category = filter_cols[1].selectbox(
        "PII / Meaning",
        [""] + options["pii_categories"],
        format_func=lambda value: value or "All",
    )
    source_type = filter_cols[2].selectbox(
        "Evidence Type",
        [""] + options["source_types"],
        format_func=lambda value: value or "All",
    )
    group_by = filter_cols[3].selectbox(
        "Group by",
        ["Job", "Table", "Column", "Match Type", "Evidence Type"],
    )
    search_mode = filter_cols[4].selectbox(
        "Search by",
        ["Text + Meaning", "Meaning only", "Text only"],
    )

    has_catalog_search = bool(query.strip() or project or pii_category or source_type)
    if has_catalog_search:
        with SessionLocal() as db:
            findings = search_catalog_findings(
                db,
                query=query,
                pii_category=pii_category,
                source_type=source_type,
                project_name=project,
                search_mode=search_mode,
            )
    else:
        findings = []

    st.subheader("Catalog Results")
    grouped_findings = group_catalog_findings_by_job(findings)
    component_match_count = count_catalog_component_matches(findings)
    st.caption(f"{len(grouped_findings)} job(s), {component_match_count} component match(es)")
    if not has_catalog_search:
        st.info("Enter a catalog search term or choose a filter to see results.")
        return
    if not findings:
        st.info("No catalog findings matched. Run Catalog Scan first if the catalog is empty.")
        return

    render_catalog_findings_by_group(findings, group_by=group_by, query=query)


def group_catalog_findings_by_job(findings) -> list[tuple[tuple[str, str, str], list]]:
    grouped = {}
    for finding in findings:
        key = (
            finding.project_name or "",
            finding.job_name or "",
            finding.file_path or "",
        )
        grouped.setdefault(key, []).append(finding)
    return sorted(grouped.items(), key=lambda item: (item[0][0], item[0][1], item[0][2]))


def group_catalog_findings(findings, group_by: str, query: str = "") -> list[tuple[str, list]]:
    grouped = {}
    for finding in findings:
        grouped.setdefault(catalog_group_label(finding, group_by, query=query), []).append(finding)
    return sorted(grouped.items(), key=lambda item: (item[0].lower(), len(item[1]) * -1))


def catalog_group_label(finding, group_by: str, query: str = "") -> str:
    if group_by == "Table":
        return finding.table_name or "No table detected"
    if group_by == "Column":
        if is_sql_keyword_catalog_field(finding.field_name):
            return f"SQL keyword: {finding.field_name}"
        return finding.field_name or "No column detected"
    if group_by == "Match Type":
        match = classify_catalog_component_match([finding], query)
        return match["label"]
    if group_by == "Evidence Type":
        return finding.source_type or "Unknown evidence type"
    return finding.job_name or "Unknown job"


def count_catalog_component_matches(findings) -> int:
    return len(
        {
            (
                finding.project_name or "",
                finding.job_name or "",
                finding.component_name or "",
                finding.component_type or "",
            )
            for finding in findings
        }
    )


def render_catalog_findings_by_group(findings, group_by: str, query: str = "") -> None:
    if group_by == "Job":
        render_grouped_catalog_results(group_catalog_findings_by_job(findings), query=query)
        return

    for group_label, group_findings in group_catalog_findings(findings, group_by, query=query):
        job_count = len(
            {
                (
                    finding.project_name or "",
                    finding.job_name or "",
                    finding.file_path or "",
                )
                for finding in group_findings
            }
        )
        component_count = count_catalog_component_matches(group_findings)
        st.markdown(
            (
                f"**{group_by}:** {group_label} "
                f"({job_count} job(s), {component_count} component match(es))"
            )
        )
        render_grouped_catalog_results(group_catalog_findings_by_job(group_findings), query=query)
        st.divider()


def render_grouped_catalog_results(grouped_findings, query: str = "") -> None:
    for (project_name, job_name, file_path), findings in grouped_findings:
        pii_labels = sorted({finding.pii_category for finding in findings if finding.pii_category})
        component_count = len({finding.component_name for finding in findings if finding.component_name})
        label = f"{job_name or 'Unknown job'} | {project_name or 'Unknown project'}"
        with st.expander(
            f"{label} ({component_count} component match(es))",
            expanded=False,
        ):
            st.caption(file_path)
            if pii_labels:
                st.write("**Detected meanings:** " + ", ".join(pii_labels))
            rows = build_catalog_component_rows(findings, query=query)
            summary_cols = st.columns(3)
            summary_cols[0].metric("Components", len(rows))
            summary_cols[1].metric("Fields", count_catalog_fields(rows))
            summary_cols[2].metric("Evidence Types", count_catalog_evidence_types(rows))
            render_catalog_component_sections(rows)


def build_catalog_component_rows(findings, query: str = "") -> list[dict]:
    grouped = {}
    for finding in findings:
        key = (
            finding.component_name or "",
            finding.component_type or "",
        )
        grouped.setdefault(key, []).append(finding)

    rows = []
    for (component_name, component_type), component_findings in sorted(grouped.items()):
        fields = dedupe_keep_order(
            [
                finding.field_name
                for finding in sorted(component_findings, key=lambda item: item.confidence, reverse=True)
                if not is_noisy_catalog_field(finding.field_name)
                and not is_sql_keyword_catalog_field(finding.field_name)
            ]
        )
        sql_keywords = dedupe_keep_order(
            [
                finding.field_name
                for finding in sorted(component_findings, key=lambda item: item.confidence, reverse=True)
                if is_sql_keyword_catalog_field(finding.field_name)
            ]
        )
        meanings = dedupe_keep_order(
            label
            for finding in component_findings
            for label in parse_json_list(finding.semantic_labels_json)
        )
        source_types = dedupe_keep_order([finding.source_type for finding in component_findings])
        directions = dedupe_keep_order([finding.direction for finding in component_findings if finding.direction])
        tables = dedupe_keep_order([finding.table_name for finding in component_findings if finding.table_name])
        evidence = pick_best_catalog_evidence(component_findings)
        match = classify_catalog_component_match(component_findings, query)
        rows.append(
            {
                "component": component_name,
                "component_type": component_type,
                "matched_fields": ", ".join(fields[:12]),
                "sql_keywords": ", ".join(sql_keywords[:12]),
                "meaning": ", ".join(meanings),
                "evidence_type": ", ".join(source_types[:4]),
                "direction": ", ".join(directions[:4]),
                "table": ", ".join(tables[:4]),
                "best_confidence": max(finding.confidence for finding in component_findings),
                "evidence": evidence,
                "match_label": match["label"],
                "match_strength": match["strength"],
                "match_detail": match["detail"],
            }
        )
    return rows


def count_catalog_fields(rows: list[dict]) -> int:
    fields = set()
    for row in rows:
        fields.update(part.strip() for part in row["matched_fields"].split(",") if part.strip())
    return len(fields)


def count_catalog_evidence_types(rows: list[dict]) -> int:
    evidence_types = set()
    for row in rows:
        evidence_types.update(part.strip() for part in row["evidence_type"].split(",") if part.strip())
    return len(evidence_types)


def summarize_catalog_components(rows: list[dict]) -> str:
    labels = ["**Components:**"]
    for row in rows[:6]:
        component = row["component"] or row["component_type"] or "component"
        fields = row["matched_fields"]
        if fields:
            labels.append(f"- {component} ({fields})")
        else:
            labels.append(f"- {component}")
    if len(rows) > 6:
        labels.append(f"- + {len(rows) - 6} more")
    return "\n".join(labels)


def render_catalog_component_sections(rows: list[dict]) -> None:
    st.write("**Components:**")
    st.markdown(
        (
            "<div style='font-size:0.84rem;margin:0.2rem 0 0.45rem;color:#4b5563'>"
            "<span style='display:inline-block;padding:0.1rem 0.45rem;border-radius:999px;background:#dcfce7;color:#166534;font-weight:600'>Exact</span> "
            "column or table name match "
            "<span style='display:inline-block;padding:0.1rem 0.45rem;border-radius:999px;background:#dbeafe;color:#1d4ed8;font-weight:600;margin-left:0.65rem'>Contains</span> "
            "partial column or table name match "
            "<span style='display:inline-block;padding:0.1rem 0.45rem;border-radius:999px;background:#fef3c7;color:#92400e;font-weight:600;margin-left:0.65rem'>Related</span> "
            "component/evidence match"
            "</div>"
        ),
        unsafe_allow_html=True,
    )
    for row in rows:
        st.markdown(build_catalog_component_details_html(row), unsafe_allow_html=True)


def build_catalog_component_detail_rows(row: dict) -> list[dict]:
    details = [
        ("Match", row["match_label"]),
        ("Matched Value", row["match_detail"]),
        ("Component Type", row["component_type"]),
        ("Detected Fields", row["matched_fields"]),
        ("SQL Keywords", row["sql_keywords"]),
        ("Meaning", row["meaning"]),
        ("Evidence Type", row["evidence_type"]),
        ("Direction", row["direction"]),
        ("Table", row["table"]),
        ("Best Confidence", f"{row['best_confidence']:.2f}"),
        ("Best Evidence", row["evidence"]),
    ]
    return [
        {"Detail": label, "Value": value}
        for label, value in details
        if str(value or "").strip()
    ]


def classify_catalog_component_match(findings, query: str) -> dict:
    if not query.strip():
        return {"label": "Filter match", "strength": "filter", "detail": ""}

    terms = build_catalog_match_terms(query)
    checks = [
        ("field", "Exact column name match", "best", lambda finding: finding.field_name),
        ("table", "Exact table name match", "best", lambda finding: finding.table_name),
        ("meaning", "Meaning match", "strong", lambda finding: " ".join(parse_json_list(finding.semantic_labels_json))),
        ("pii", "PII category match", "strong", lambda finding: finding.pii_category),
        ("evidence_type", "Evidence type match", "related", lambda finding: finding.source_type),
        ("component", "Component match", "related", lambda finding: f"{finding.component_name or ''} {finding.component_type or ''}"),
        ("job", "Job name match", "related", lambda finding: finding.job_name),
        ("evidence", "Evidence text match", "related", lambda finding: finding.evidence_text),
    ]

    for _, label, strength, getter in checks:
        for finding in findings:
            value = getter(finding) or ""
            if catalog_value_matches(value, terms, exact=True):
                return {"label": label, "strength": strength, "detail": str(value)}

    for _, label, strength, getter in checks:
        for finding in findings:
            value = getter(finding) or ""
            if catalog_value_matches(value, terms, exact=False):
                partial_strength = "strong" if strength == "best" else strength
                partial_label = (
                    label.replace("Exact ", "").replace(" match", " contains").capitalize()
                    if strength == "best"
                    else label.replace(" match", " contains")
                )
                return {"label": partial_label, "strength": partial_strength, "detail": str(value)}

    return {"label": "Filter match", "strength": "filter", "detail": ""}


def build_catalog_match_terms(query: str) -> list[str]:
    raw = str(query or "").strip().lower()
    normalized = normalize_catalog_match_text(raw)
    compact = normalized.replace(" ", "")
    return dedupe_keep_order([term for term in [raw, normalized, compact] if term])


def catalog_value_matches(value: str, terms: list[str], exact: bool) -> bool:
    raw = str(value or "").strip().lower()
    normalized = normalize_catalog_match_text(raw)
    compact = normalized.replace(" ", "")
    values = {raw, normalized, compact}
    if exact:
        return any(term in values for term in terms)
    return any(term and any(term in value_part for value_part in values) for term in terms)


def normalize_catalog_match_text(value: str) -> str:
    return " ".join(str(value or "").lower().replace("_", " ").replace("-", " ").split())


def render_catalog_match_badge(row: dict) -> None:
    styles = {
        "best": ("#dcfce7", "#166534"),
        "strong": ("#dbeafe", "#1d4ed8"),
        "related": ("#fef3c7", "#92400e"),
        "filter": ("#f3f4f6", "#374151"),
    }
    background, color = styles.get(row["match_strength"], styles["filter"])
    label = html.escape(row["match_label"] or "Filter match")
    detail = html.escape(row["match_detail"] or "")
    suffix = f" <span style='color:#4b5563'>{detail}</span>" if detail else ""
    st.markdown(
        (
            f"<span style='display:inline-block;padding:0.2rem 0.55rem;"
            f"border-radius:999px;background:{background};color:{color};"
            f"font-size:0.82rem;font-weight:600'>{label}</span>{suffix}"
        ),
        unsafe_allow_html=True,
    )


def build_catalog_component_details_html(row: dict) -> str:
    styles = {
        "best": ("#dcfce7", "#166534", "#bbf7d0"),
        "strong": ("#dbeafe", "#1d4ed8", "#bfdbfe"),
        "related": ("#fef3c7", "#92400e", "#fde68a"),
        "filter": ("#f3f4f6", "#374151", "#e5e7eb"),
    }
    background, color, border = styles.get(row["match_strength"], styles["filter"])
    component = html.escape(row["component"] or row["component_type"] or "component")
    fields = html.escape(row["matched_fields"])
    match_label = html.escape(row["match_label"] or "Filter match")
    match_detail = html.escape(row["match_detail"] or "")
    title = component if not fields else f"{component} ({fields})"
    detail_suffix = f" - {match_detail}" if match_detail else ""
    detail_rows = "".join(
        "<tr>"
        f"<td style='width:160px;padding:0.35rem 0.55rem;border-top:1px solid #e5e7eb;color:#374151;font-weight:600'>{html.escape(item['Detail'])}</td>"
        f"<td style='padding:0.35rem 0.55rem;border-top:1px solid #e5e7eb;color:#111827'>{html.escape(str(item['Value']))}</td>"
        "</tr>"
        for item in build_catalog_component_detail_rows(row)
    )
    return (
        f"<details style='border:1px solid {border};border-radius:0.45rem;margin:0.35rem 0;background:#ffffff'>"
        f"<summary style='cursor:pointer;list-style-position:inside;padding:0.55rem 0.7rem;background:{background};color:{color};font-weight:650'>"
        f"<span>{match_label}{detail_suffix}</span>"
        f"<span style='color:#111827;font-weight:500'> | {title}</span>"
        "</summary>"
        "<table style='width:100%;border-collapse:collapse;font-size:0.92rem'>"
        f"{detail_rows}"
        "</table>"
        "</details>"
    )


def pick_best_catalog_evidence(findings) -> str:
    ordered = sorted(findings, key=lambda item: item.confidence, reverse=True)
    for finding in ordered:
        if finding.evidence_text:
            return finding.evidence_text
    return ""


def is_noisy_catalog_field(value: str) -> bool:
    return str(value or "").lower() in {
        "get",
        "put",
        "int",
        "string",
        "long",
        "double",
        "float",
        "boolean",
        "globalmap",
        "context",
        "system",
    }


def is_sql_keyword_catalog_field(value: str) -> bool:
    return str(value or "").upper() in {
        "ALL",
        "AND",
        "ANY",
        "AS",
        "ASC",
        "BETWEEN",
        "BY",
        "CASE",
        "CAST",
        "CREATE",
        "DELETE",
        "DESC",
        "DISTINCT",
        "ELSE",
        "END",
        "EXISTS",
        "FROM",
        "GROUP",
        "HAVING",
        "IN",
        "INNER",
        "INSERT",
        "INTO",
        "IS",
        "JOIN",
        "LEFT",
        "LIKE",
        "LIMIT",
        "NOT",
        "NULL",
        "ON",
        "OR",
        "ORDER",
        "OUTER",
        "RETURNING",
        "RIGHT",
        "SELECT",
        "SET",
        "THEN",
        "UNION",
        "UPDATE",
        "VALUES",
        "WHEN",
        "WHERE",
        "WITH",
    }


section = st.radio(
    "Section",
    ["Knowledge Base", "Vulnerability Scan", "Data Catalog"],
    horizontal=True,
    label_visibility="collapsed",
    key="app_section",
)

if section != "Knowledge Base":
    st.session_state["selected_artifact_id"] = None

if section == "Knowledge Base":
    render_kb_page()
elif section == "Vulnerability Scan":
    render_vulnerability_page()
else:
    render_catalog_page()
