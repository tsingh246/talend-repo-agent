from __future__ import annotations

import re
from typing import Any


COMPONENT_INSTANCE_REGEX = re.compile(r"^(t[A-Z][A-Za-z0-9]*)(?:_\d+)?$")


def build_summary(artifact_type: str, parsed: dict[str, Any]) -> tuple[str, str, str, str]:
    raw_components = parsed.get("component_types", [])
    urls = parsed.get("urls", [])
    context_refs = parsed.get("context_refs", [])
    sql_snippets = parsed.get("sql_snippets", [])
    code_snippets = parsed.get("code_snippets", [])
    text_samples = parsed.get("text_samples", [])
    method_names = parsed.get("method_names", [])
    imports = parsed.get("imports", [])
    string_literals = parsed.get("string_literals", [])
    code_keywords = parsed.get("code_keywords", [])
    auth_signals = parsed.get("auth_signals", [])
    external_systems = parsed.get("external_systems", [])
    class_names = parsed.get("class_names", [])
    parameter_names = parsed.get("parameter_names", [])
    qualified_class_refs = parsed.get("qualified_class_refs", [])

    normalized_components = normalize_summary_components(raw_components)

    if artifact_type == "job":
        summary = build_job_summary(
            normalized_components,
            urls,
            context_refs,
            sql_snippets,
            code_snippets,
            auth_signals,
            external_systems,
        )
    elif artifact_type == "joblet":
        summary = build_joblet_summary(
            normalized_components, urls, context_refs, sql_snippets, code_snippets
        )
    elif artifact_type == "routine":
        summary = build_routine_summary(
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

    search_text = build_search_text(
        artifact_type=artifact_type,
        summary=summary,
        normalized_components=normalized_components,
        urls=urls,
        context_refs=context_refs,
        sql_snippets=sql_snippets,
        auth_signals=auth_signals,
        external_systems=external_systems,
        method_names=method_names,
        code_keywords=code_keywords,
        class_names=class_names,
        parameter_names=parameter_names,
        qualified_class_refs=qualified_class_refs,
        string_literals=string_literals,
    )

    embedding_text = build_embedding_text(
        artifact_type=artifact_type,
        name=parsed.get("name", ""),
        summary=summary,
        normalized_components=normalized_components,
        urls=urls,
        context_refs=context_refs,
        sql_snippets=sql_snippets,
        auth_signals=auth_signals,
        external_systems=external_systems,
        method_names=method_names,
        code_keywords=code_keywords,
        class_names=class_names,
        parameter_names=parameter_names,
        qualified_class_refs=qualified_class_refs,
    )

    component_text = ", ".join(normalized_components[:15])

    return summary, search_text, component_text, embedding_text


def build_search_text(
    artifact_type: str,
    summary: str,
    normalized_components: list[str],
    urls: list[str],
    context_refs: list[str],
    sql_snippets: list[str],
    auth_signals: list[str],
    external_systems: list[str],
    method_names: list[str],
    code_keywords: list[str],
    class_names: list[str],
    parameter_names: list[str],
    qualified_class_refs: list[str],
    string_literals: list[str],
) -> str:
    parts: list[str] = [summary]

    parts.extend(normalized_components[:15])
    parts.extend(context_refs[:15])
    parts.extend(auth_signals[:10])
    parts.extend(external_systems[:10])
    parts.extend(method_names[:10])
    parts.extend(class_names[:5])
    parts.extend(code_keywords[:15])
    parts.extend(parameter_names[:15])
    parts.extend(shorten_refs(qualified_class_refs[:15]))

    if artifact_type != "routine":
        parts.extend(urls[:8])
        parts.extend(build_sql_search_signals(sql_snippets[:3]))
    else:
        parts.extend(filter_string_literals(string_literals[:10]))

    return compact_join(parts)


def build_sql_search_signals(sql_snippets: list[str]) -> list[str]:
    signals: list[str] = []
    for sql in sql_snippets:
        normalized_sql = " ".join(sql.split()).lower()
        operation = infer_sql_operation(normalized_sql)
        table = extract_primary_table(normalized_sql)
        if table:
            signals.append(f"sql_{operation}_{table}")
        else:
            signals.append(f"sql_{operation}")
        preview = build_sql_preview(normalized_sql)
        if preview:
            signals.append(f"sql_preview_{preview}")
    return dedupe_keep_order(signals)


def build_sql_preview(sql: str) -> str:
    # Keep structural SQL context, drop noisy literals.
    collapsed = re.sub(r"'[^']*'", " ", sql)
    collapsed = re.sub(r'"[^"]*"', " ", collapsed)
    collapsed = re.sub(r"[^a-z0-9_.,\s]", " ", collapsed)
    collapsed = re.sub(r"\s+", " ", collapsed).strip()
    if not collapsed:
        return ""

    preview_tokens: list[str] = []
    for token in collapsed.split():
        if token in {"select", "from", "where", "group", "by", "join", "on", "insert", "into", "update", "set", "delete"}:
            preview_tokens.append(token)
            continue
        if re.match(r"^[a-z_][a-z0-9_.]*$", token):
            preview_tokens.append(token)
        if len(preview_tokens) >= 12:
            break

    return "_".join(preview_tokens[:12])


def build_embedding_text(
    artifact_type: str,
    name: str,
    summary: str,
    normalized_components: list[str],
    urls: list[str],
    context_refs: list[str],
    sql_snippets: list[str],
    auth_signals: list[str],
    external_systems: list[str],
    method_names: list[str],
    code_keywords: list[str],
    class_names: list[str],
    parameter_names: list[str],
    qualified_class_refs: list[str],
) -> str:
    parts: list[str] = []

    if name:
        parts.append(f"Artifact name: {name}")
    parts.append(f"Artifact type: {artifact_type}")
    parts.append(summary)

    if normalized_components:
        parts.append("Main Talend components: " + ", ".join(normalized_components[:10]))

    if method_names:
        parts.append("Routine methods: " + ", ".join(method_names[:8]))

    if class_names:
        parts.append("Routine classes: " + ", ".join(class_names[:5]))

    if code_keywords:
        parts.append("Technical keywords: " + ", ".join(code_keywords[:10]))

    if parameter_names and artifact_type == "routine":
        parts.append("Routine parameters: " + ", ".join(parameter_names[:10]))

    if qualified_class_refs and artifact_type == "routine":
        parts.append("Referenced classes/libraries: " + ", ".join(shorten_refs(qualified_class_refs[:8])))

    if context_refs:
        parts.append("Context references detected.")

    if sql_snippets:
        parts.append("SQL logic detected.")

    if auth_signals:
        parts.append("Authentication signals: " + ", ".join(auth_signals[:6]))

    if external_systems:
        parts.append("External systems: " + ", ".join(external_systems[:6]))

    if urls and artifact_type != "routine":
        parts.append("URL or API-related configuration detected.")

    return " ".join(parts)


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


def compact_join(values: list[str]) -> str:
    seen = set()
    output = []
    for value in values:
        v = " ".join(str(value).split()).strip()
        if not v:
            continue
        lower = v.lower()
        if lower not in seen:
            seen.add(lower)
            output.append(v)
    return " ".join(output)


def normalize_summary_components(values: list[str]) -> list[str]:
    normalized: list[str] = []

    for value in values:
        v = value.strip()
        match = COMPONENT_INSTANCE_REGEX.match(v)
        if not match:
            continue
        normalized.append(match.group(1))

    return dedupe_keep_order(normalized)


def build_job_summary(
    component_types: list[str],
    urls: list[str],
    context_refs: list[str],
    sql_snippets: list[str],
    code_snippets: list[str],
    auth_signals: list[str],
    external_systems: list[str],
) -> str:
    category = infer_job_category(component_types, urls, sql_snippets, code_snippets)
    components_text = format_component_list(component_types[:8])
    signals = infer_job_signals(component_types, urls, context_refs, sql_snippets, code_snippets)
    source_text, target_text = infer_job_io(component_types)
    flow_steps = infer_job_flow_steps(component_types, sql_snippets, urls)
    sql_human_summary = summarize_sql_intent(sql_snippets[0]) if sql_snippets else ""

    parts = [f"Talend job for {category}"]

    if components_text:
        parts.append(f"using {components_text}")

    if source_text or target_text:
        if source_text and target_text:
            parts.append(f"Likely flow: source {source_text} to target {target_text}")
        elif source_text:
            parts.append(f"Likely source: {source_text}")
        elif target_text:
            parts.append(f"Likely target: {target_text}")

    if flow_steps:
        parts.append(f"Main ETL steps: {' -> '.join(flow_steps[:5])}")

    if sql_human_summary:
        parts.append(f"SQL intent: {sql_human_summary}")

    if auth_signals:
        parts.append(f"Auth/security signals: {format_plain_list(auth_signals[:4])}")

    if external_systems:
        parts.append(f"External systems: {format_plain_list(external_systems[:4])}")

    if signals:
        parts.append(f"Detected: {', '.join(signals)}")

    return ". ".join(parts) + "."


def build_joblet_summary(
    component_types: list[str],
    urls: list[str],
    context_refs: list[str],
    sql_snippets: list[str],
    code_snippets: list[str],
) -> str:
    category = infer_joblet_category(component_types, urls, sql_snippets, code_snippets)
    components_text = format_component_list(component_types[:8])
    signals = infer_job_signals(component_types, urls, context_refs, sql_snippets, code_snippets)

    parts = [f"Talend joblet for {category}"]

    if components_text:
        parts.append(f"using {components_text}")

    if signals:
        parts.append(f"Detected: {', '.join(signals)}")

    return ". ".join(parts) + "."


def build_routine_summary(
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

    parts = [f"Talend routine for {category}"]

    details = []

    if class_names:
        details.append(f"class {format_plain_list(class_names[:2])}")

    if method_names:
        details.append(f"methods such as {format_plain_list(method_names[:4])}")

    if parameter_names:
        details.append(f"parameters including {format_plain_list(parameter_names[:6])}")

    if code_keywords:
        details.append(f"keywords/signals: {format_plain_list(code_keywords[:8])}")

    if qualified_class_refs:
        details.append(f"Java/AWS references such as {format_plain_list(shorten_refs(qualified_class_refs[:4]))}")

    if urls:
        details.append("URL/API-related strings detected")

    if context_refs:
        details.append("context variable references detected")

    if details:
        parts.append("with " + "; ".join(details))

    return ". ".join(parts) + "."


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

    if any(x in signals_blob for x in ["s3", "presigned", "bucket", "aws", "amazon"]):
        return "AWS S3 helper processing"
    if any(x in signals_blob for x in ["vault", "token", "secret", "auth", "password"]):
        return "authentication/secret handling"
    if any(x in signals_blob for x in ["http", "https", "api", "rest", "request", "response", "url"]):
        return "API/helper processing"
    if any(x in signals_blob for x in ["json", "xml"]):
        return "data parsing/transformation"
    if any(x in signals_blob for x in ["file", "path", "directory"]):
        return "file/path utility logic"
    if any(x in signals_blob for x in ["oracle", "jdbc", "sql", "query"]):
        return "database/helper processing"

    return "custom utility logic"


def shorten_refs(values: list[str]) -> list[str]:
    result = []
    for value in values:
        parts = value.split(".")
        result.append(parts[-1] if parts else value)
    return result


def format_plain_list(values: list[str]) -> str:
    if not values:
        return ""
    if len(values) == 1:
        return values[0]
    if len(values) == 2:
        return f"{values[0]} and {values[1]}"
    return ", ".join(values[:-1]) + f", and {values[-1]}"


def infer_job_category(
    component_types: list[str],
    urls: list[str],
    sql_snippets: list[str],
    code_snippets: list[str],
) -> str:
    comp_set = set(component_types)

    db_tech = detect_database_technology(component_types)
    if db_tech:
        return f"{db_tech} database processing"

    if has_api_components(comp_set):
        return "REST API processing"

    if {"tExtractJSONFields", "tWriteJSONField"} & comp_set:
        return "JSON processing"

    if {"tDBInput", "tDBOutput", "tDBRow"} & comp_set or sql_snippets:
        return "database processing"

    if {"tFileInputDelimited", "tFileOutputDelimited"} & comp_set:
        return "file processing"

    if {"tMap", "tJavaRow"} & comp_set:
        return "data transformation"

    if "tSystem" in comp_set:
        return "system command execution"

    return "integration processing"


def infer_joblet_category(
    component_types: list[str],
    urls: list[str],
    sql_snippets: list[str],
    code_snippets: list[str],
) -> str:
    comp_set = set(component_types)

    if has_api_components(comp_set):
        return "REST/API handling"
    if {"tLogRow", "tFlowMeterCatcher"} & comp_set:
        return "logging/monitoring"
    if {"tMap", "tXMLMap"} & comp_set:
        return "transformation"
    if {"tJava", "tJavaRow"} & comp_set or code_snippets:
        return "custom logic"
    if sql_snippets:
        return "database/SQL handling"

    return "reusable processing"


def infer_job_signals(
    component_types: list[str],
    urls: list[str],
    context_refs: list[str],
    sql_snippets: list[str],
    code_snippets: list[str],
) -> list[str]:
    signals: list[str] = []
    comp_set = set(component_types)

    if has_api_components(comp_set):
        signals.append("REST/API handling")
    if {"tExtractJSONFields", "tWriteJSONField"} & comp_set:
        signals.append("JSON handling")
    if {"tXMLMap", "tExtractXMLField"} & comp_set:
        signals.append("XML handling")
    if {"tMap"} & comp_set:
        signals.append("data mapping")
    if has_custom_java_components(comp_set):
        signals.append("custom Java logic")
    if sql_snippets:
        signals.append("SQL logic")
    if context_refs:
        signals.append("context variable usage")

    return signals[:5]


def infer_job_io(component_types: list[str]) -> tuple[str, str]:
    source_hints = detect_component_hints(component_types, "Input")
    target_hints = detect_component_hints(component_types, "Output")

    source_text = format_plain_list(source_hints[:3]) if source_hints else ""
    target_text = format_plain_list(target_hints[:3]) if target_hints else ""
    return source_text, target_text


def infer_job_flow_steps(
    component_types: list[str],
    sql_snippets: list[str],
    urls: list[str],
) -> list[str]:
    comp_set = set(component_types)
    steps: list[str] = []

    input_hints = detect_component_hints(component_types, "Input")
    output_hints = detect_component_hints(component_types, "Output")

    if input_hints:
        steps.append("extract from " + format_plain_list(input_hints[:2]))

    if {"tMap", "tXMLMap"} & comp_set:
        steps.append("transform/map data")
    if {"tFilterRow", "tReplicate"} & comp_set:
        steps.append("filter/route records")
    if has_custom_java_components(comp_set):
        steps.append("apply custom Java logic")
    if sql_snippets:
        steps.append("execute SQL operations")
    if has_api_components(comp_set):
        steps.append("exchange data via API")

    if output_hints:
        steps.append("load to " + format_plain_list(output_hints[:2]))

    return dedupe_keep_order(steps)


def summarize_sql_intent(sql: str) -> str:
    normalized_sql = " ".join(sql.split())
    lower_sql = normalized_sql.lower()

    operation = infer_sql_operation(lower_sql)
    primary_table = extract_primary_table(lower_sql)
    joined_tables = extract_join_tables(lower_sql)
    selected_fields = extract_selected_fields(lower_sql)
    has_filter = bool(re.search(r"\bwhere\b", lower_sql))
    has_grouping = bool(re.search(r"\bgroup\s+by\b", lower_sql))

    parts: list[str] = [f"{operation} query"]

    if primary_table:
        parts.append(f"on `{primary_table}`")
    if joined_tables:
        parts.append("joining " + format_plain_list([f"`{name}`" for name in joined_tables[:3]]))
    if selected_fields:
        parts.append("selecting fields " + format_plain_list([f"`{name}`" for name in selected_fields[:5]]))
    if has_filter:
        parts.append("with row filtering")
    if has_grouping:
        parts.append("with aggregation/grouping")

    return " ".join(parts)


def infer_sql_operation(sql: str) -> str:
    if re.search(r"\binsert\b", sql):
        return "insert"
    if re.search(r"\bupdate\b", sql):
        return "update"
    if re.search(r"\bdelete\b", sql):
        return "delete"
    if re.search(r"\bmerge\b", sql):
        return "merge"
    return "select"


def extract_primary_table(sql: str) -> str:
    for pattern in [
        r"\bfrom\s+([a-zA-Z0-9_.\"`]+)",
        r"\bupdate\s+([a-zA-Z0-9_.\"`]+)",
        r"\binto\s+([a-zA-Z0-9_.\"`]+)",
    ]:
        match = re.search(pattern, sql)
        if match:
            return clean_sql_identifier(match.group(1))
    return ""


def extract_join_tables(sql: str) -> list[str]:
    matches = re.findall(r"\bjoin\s+([a-zA-Z0-9_.\"`]+)", sql)
    return dedupe_keep_order([clean_sql_identifier(m) for m in matches if m])


def extract_selected_fields(sql: str) -> list[str]:
    match = re.search(r"\bselect\s+(.*?)\s+\bfrom\b", sql, re.IGNORECASE)
    if not match:
        return []

    raw_fields = match.group(1).strip()
    if not raw_fields or raw_fields == "*":
        return []

    fields: list[str] = []
    for chunk in raw_fields.split(","):
        token = chunk.strip()
        if not token:
            continue
        token = re.sub(r"\s+as\s+[a-zA-Z0-9_\"`]+$", "", token, flags=re.IGNORECASE)
        token = token.split()[-1]
        cleaned = clean_sql_identifier(token)
        if is_useful_sql_field(cleaned):
            fields.append(cleaned)

    return dedupe_keep_order([f for f in fields if f and f != "*"])


def clean_sql_identifier(value: str) -> str:
    return value.strip().strip("`").strip('"')


def is_useful_sql_field(value: str) -> bool:
    if not value or value == "*":
        return False
    if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_.]*$", value):
        return False
    reserved_tokens = {"and", "or", "case", "when", "then", "end", "null"}
    return value.lower() not in reserved_tokens


def has_api_components(comp_set: set[str]) -> bool:
    return bool({"tRESTRequest", "tRESTResponse", "tRESTClient", "tHttpRequest"} & comp_set)


def has_custom_java_components(comp_set: set[str]) -> bool:
    return bool({"tJava", "tJavaRow", "tJavaFlex"} & comp_set)


def detect_component_hints(component_types: list[str], suffix: str) -> list[str]:
    hints: list[str] = []
    for comp in component_types:
        if not comp.endswith(suffix):
            continue
        core = comp[1 : -len(suffix)] if comp.startswith("t") else comp[: -len(suffix)]
        core = core.strip()
        if not core:
            continue
        hints.append(normalize_component_hint(core))
    return dedupe_keep_order(hints)


def normalize_component_hint(value: str) -> str:
    normalized = re.sub(r"([a-z])([A-Z])", r"\1 \2", value)
    normalized = normalized.replace("Db", "DB")
    return normalized.lower()


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


def detect_database_technology(component_types: list[str]) -> str | None:
    db_map = {
        "Oracle": ["tOracleInput", "tOracleOutput", "tOracleConnection"],
        "HSQLDB": ["tHSQLDbInput", "tHSQLDbOutput"],
        "MySQL": ["tMysqlInput", "tMysqlOutput", "tMysqlConnection"],
        "PostgreSQL": ["tPostgresqlInput", "tPostgresqlOutput", "tPostgresqlConnection"],
        "MSSQL": ["tMSSqlInput", "tMSSqlOutput", "tMSSqlConnection"],
        "Snowflake": ["tSnowflakeInput", "tSnowflakeOutput", "tSnowflakeConnection"],
    }

    comp_set = set(component_types)

    for db_name, indicators in db_map.items():
        if any(indicator in comp_set for indicator in indicators):
            return db_name

    return None