from __future__ import annotations

import html
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


URL_REGEX = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
CONTEXT_REGEX = re.compile(r"context\.[A-Za-z0-9_]+")
SQL_REGEX = re.compile(r"\b(select|insert|update|delete)\b", re.IGNORECASE)
SQL_STATEMENT_REGEX = re.compile(
    r"\bselect\b[\s\S]{0,2000}?\bfrom\b|\binsert\b\s+into\b|\bupdate\b[\s\S]{0,500}?\bset\b|\bdelete\b\s+from\b|\bmerge\b\s+into\b",
    re.IGNORECASE,
)

JAVA_METHOD_REGEX = re.compile(
    r"(?:public|private|protected)?\s*(?:static\s+)?[\w<>\[\]]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)",
    re.DOTALL,
)

JAVA_CLASS_REGEX = re.compile(r"\bclass\s+([A-Za-z_][A-Za-z0-9_]*)\b")
JAVA_IMPORT_REGEX = re.compile(r"import\s+([A-Za-z0-9_.*]+);")
JAVA_QUALIFIED_REF_REGEX = re.compile(r"\b(?:[a-z_][a-z0-9_]*\.)+[A-Z][A-Za-z0-9_]*\b")
JAVA_STRING_LITERAL_REGEX = re.compile(r'"([^"]{3,300})"')
JAVA_PARAM_NAME_REGEX = re.compile(r"(?:final\s+)?[\w<>\[\].]+\s+([A-Za-z_][A-Za-z0-9_]*)\s*$")

COMPONENT_REGEX = re.compile(r"^(t[A-Z][A-Za-z0-9]*)(?:_\d+)?$")
DB_INPUT_COMPONENT_REGEX = re.compile(
    r"^t(?:DB|Jdbc|Oracle|Mysql|Postgresql|MSSql|Snowflake|Netezza|Teradata)[A-Za-z0-9]*Input$",
    re.IGNORECASE,
)


def parse_item_file(file_path: str, artifact_type: str) -> dict[str, Any]:
    path = Path(file_path)

    empty_result = {
        "name": path.stem,
        "component_types": [],
        "labels": [],
        "urls": [],
        "context_refs": [],
        "sql_snippets": [],
        "text_samples": [],
        "code_snippets": [],
        "method_names": [],
        "imports": [],
        "string_literals": [],
        "code_keywords": [],
        "auth_signals": [],
        "external_systems": [],
        "class_names": [],
        "parameter_names": [],
        "qualified_class_refs": [],
    }

    if not path.exists():
        return empty_result

    try:
        raw_text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        raw_text = ""

    all_text_values: list[str] = []
    component_types: list[str] = []
    labels: list[str] = []
    code_snippets: list[str] = []
    db_input_sql_snippets: list[str] = []

    # Try XML parse, but do NOT exit if it fails
    root = None
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except Exception:
        root = None

    # XML-backed artifacts
    if root is not None:
        db_input_sql_snippets = extract_db_input_sql_from_xml(root)

        for elem in root.iter():
            for value in elem.attrib.values():
                if value and isinstance(value, str):
                    stripped = value.strip()
                    all_text_values.append(stripped)

                    if looks_like_code(stripped):
                        code_snippets.append(clean_snippet(stripped, max_len=2000))

            if elem.text and elem.text.strip():
                stripped = elem.text.strip()
                all_text_values.append(stripped)

                if looks_like_code(stripped):
                    code_snippets.append(clean_snippet(stripped, max_len=2000))

            for key, value in elem.attrib.items():
                lower_key = key.lower()
                if lower_key in {"componentname", "component_name", "family", "type", "name"}:
                    if isinstance(value, str):
                        normalized = normalize_component_name(value.strip())
                        if normalized:
                            component_types.append(normalized)

            for key, value in elem.attrib.items():
                lower_key = key.lower()
                if lower_key in {"label", "displayname", "name"} and value:
                    labels.append(str(value).strip())

    # Always inspect raw text for routines. For jobs/joblets we rely on XML values
    # to avoid adding noisy full-document snippets into search signals.
    if raw_text:
        if artifact_type == "routine":
            all_text_values.append(raw_text)
            code_snippets.append(clean_snippet(raw_text, max_len=3000))

    all_text_values = dedupe_keep_order([x for x in all_text_values if x])
    component_types = dedupe_keep_order(component_types)
    labels = dedupe_keep_order(labels)
    code_snippets = dedupe_keep_order(code_snippets)

    urls = extract_urls(all_text_values)
    context_refs = extract_context_refs(all_text_values)
    sql_snippets = extract_sql_snippets(all_text_values)
    sql_snippets = dedupe_keep_order(db_input_sql_snippets + sql_snippets)
    text_samples = pick_interesting_text_samples(all_text_values)
    auth_signals = extract_auth_signals(all_text_values, urls, component_types)
    external_systems = extract_external_systems(
        urls=urls,
        component_types=component_types,
        sql_snippets=sql_snippets,
        code_snippets=code_snippets,
    )

    method_names: list[str] = []
    imports: list[str] = []
    string_literals: list[str] = []
    code_keywords: list[str] = []
    class_names: list[str] = []
    parameter_names: list[str] = []
    qualified_class_refs: list[str] = []

    if artifact_type == "routine":
        routine_source = "\n".join(all_text_values + code_snippets)
        class_names = extract_class_names(routine_source)
        method_names, parameter_names = extract_methods_and_params(routine_source)
        imports = extract_imports(routine_source)
        qualified_class_refs = extract_qualified_class_refs(routine_source)
        string_literals = extract_string_literals(routine_source)
        code_keywords = extract_code_keywords(
            routine_source,
            class_names=class_names,
            method_names=method_names,
            parameter_names=parameter_names,
            qualified_class_refs=qualified_class_refs,
            string_literals=string_literals,
        )

    return {
        "name": path.stem,
        "component_types": component_types[:30],
        "labels": labels[:30],
        "urls": urls[:20],
        "context_refs": context_refs[:30],
        "sql_snippets": sql_snippets[:10],
        "text_samples": text_samples[:20],
        "code_snippets": code_snippets[:10],
        "method_names": method_names[:20],
        "imports": imports[:20],
        "string_literals": string_literals[:20],
        "code_keywords": code_keywords[:30],
        "auth_signals": auth_signals[:20],
        "external_systems": external_systems[:20],
        "class_names": class_names[:10],
        "parameter_names": parameter_names[:30],
        "qualified_class_refs": qualified_class_refs[:30],
    }

def normalize_component_name(value: str) -> str | None:
    value = value.strip()
    match = COMPONENT_REGEX.match(value)
    if match:
        return match.group(1)
    return None


def looks_like_code(text: str) -> bool:
    sample = text.strip()
    if len(sample) < 20:
        return False

    indicators = [
        "public ",
        "private ",
        "protected ",
        "class ",
        "if (",
        "for (",
        "while (",
        "return ",
        "globalMap",
        "context.",
        "import ",
        "static ",
        "new ",
        "com.amazonaws",
    ]
    hit_count = sum(1 for token in indicators if token in sample)
    return hit_count >= 2


def clean_snippet(text: str, max_len: int = 500) -> str:
    cleaned = " ".join(text.strip().split())
    return cleaned[:max_len]


def extract_urls(text_values: list[str]) -> list[str]:
    results: list[str] = []
    for value in text_values:
        for candidate in URL_REGEX.findall(value):
            if is_informative_url(candidate):
                results.append(candidate)
    return dedupe_keep_order(results)


def is_informative_url(url: str) -> bool:
    lower = url.lower()
    ignored_markers = [
        "omg.org",
        "eclipse.org",
        "talend.org",
    ]
    return not any(marker in lower for marker in ignored_markers)


def extract_context_refs(text_values: list[str]) -> list[str]:
    results: list[str] = []
    for value in text_values:
        results.extend(CONTEXT_REGEX.findall(value))
    return dedupe_keep_order(results)


def extract_sql_snippets(text_values: list[str]) -> list[str]:
    results: list[str] = []
    for value in text_values:
        if looks_like_sql_statement(value):
            snippet = normalize_sql_snippet(value, max_len=400)
            if is_valid_sql_snippet(snippet):
                results.append(snippet)
    return dedupe_keep_order(results)


def extract_auth_signals(
    text_values: list[str],
    urls: list[str],
    component_types: list[str],
) -> list[str]:
    corpus = " ".join(text_values + urls).lower()
    markers = {
        "oauth": [
            r"\boauth\b",
            r"oauth2",
            r"/services/oauth2",
            r"grant[_-]?type",
            r"access[_-]?token",
        ],
        "bearer_token": [r"\bbearer\b", r"authorization:\s*bearer", r"x-auth-token"],
        "basic_auth": [r"\bbasic auth\b", r"authorization:\s*basic"],
        "vault_secret": [r"\bvault\b", r"hashicorp", r"x-vault-token", r"/v1/secret", r"/v1/kv"],
        "api_key": [r"\bapi[_-]?key\b", r"x-api-key"],
    }
    results: list[str] = []
    for signal, patterns in markers.items():
        if any(re.search(pattern, corpus, re.IGNORECASE) for pattern in patterns):
            results.append(signal)

    # Salesforce connector jobs commonly use OAuth even if endpoint strings are sparse.
    if (
        "oauth" not in results
        and any(c.startswith("tSalesforce") for c in component_types)
    ):
        results.append("oauth")
    return dedupe_keep_order(results)


def extract_external_systems(
    urls: list[str],
    component_types: list[str],
    sql_snippets: list[str],
    code_snippets: list[str],
) -> list[str]:
    url_blob = " ".join(urls).lower()
    sql_blob = " ".join(sql_snippets).lower()
    code_blob = " ".join(code_snippets).lower()
    results: list[str] = []

    if any(c.startswith("tSnowflake") for c in component_types) or "snowflake" in url_blob or "snowflake" in sql_blob:
        results.append("snowflake")

    if (
        any(c.startswith("tOracle") for c in component_types)
        or "jdbc:oracle:" in sql_blob
        or "jdbc:oracle:" in code_blob
    ):
        results.append("oracle")

    if any(c.startswith("tSalesforce") for c in component_types) or "salesforce" in url_blob:
        results.append("salesforce")

    if "hashicorp" in code_blob or "vault" in code_blob or "/v1/secret" in url_blob:
        results.append("hashicorp_vault")

    if (
        any(c.startswith("tS3") for c in component_types)
        or "amazonaws.com" in url_blob
        or re.search(r"\baws\b", code_blob) is not None
    ):
        results.append("aws")

    if "servicenow" in url_blob or "servicenow" in code_blob:
        results.append("servicenow")

    return dedupe_keep_order(results)


def extract_db_input_sql_from_xml(root: ET.Element) -> list[str]:
    results: list[str] = []

    for elem in root.iter():
        component_name = ""
        for key, value in elem.attrib.items():
            if key.lower() in {"componentname", "component_name", "type", "name"} and isinstance(value, str):
                normalized = normalize_component_name(value.strip())
                if normalized:
                    component_name = normalized
                    break

        if not component_name or not DB_INPUT_COMPONENT_REGEX.match(component_name):
            continue

        for node in elem.iter():
            attr_name = str(
                node.attrib.get("name")
                or node.attrib.get("field")
                or node.attrib.get("key")
                or ""
            ).strip().lower()

            candidate_values: list[str] = []
            for attr_key, attr_value in node.attrib.items():
                if not isinstance(attr_value, str):
                    continue
                if attr_key.lower() in {"value", "defaultvalue", "rawvalue", "expression"}:
                    candidate_values.append(attr_value)

            if node.text and isinstance(node.text, str):
                candidate_values.append(node.text)

            for candidate in candidate_values:
                text = normalize_memo_sql_value(candidate)
                if not text:
                    continue
                if (
                    attr_name in {"query", "sql", "statement", "querystring", "query_text"}
                    or "query" in attr_name
                    or "sql" in attr_name
                    or looks_like_sql_statement(text)
                ):
                    if looks_like_sql_statement(text):
                        snippet = normalize_sql_snippet(text, max_len=700)
                        if is_valid_sql_snippet(snippet):
                            results.append(snippet)

    return dedupe_keep_order(results)


def looks_like_sql_statement(text: str) -> bool:
    sample = " ".join(text.split())
    return bool(SQL_STATEMENT_REGEX.search(sample))


def normalize_memo_sql_value(raw_value: str) -> str:
    text = html.unescape(raw_value).strip()
    text = text.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\r", "\n")
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # Talend MEMO_SQL values are often wrapped in extra quotes.
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        text = text[1:-1].strip()

    return text


def normalize_sql_snippet(text: str, max_len: int) -> str:
    snippet = clean_snippet(text, max_len=max_len)
    return snippet.strip().strip('"').strip("'")


def is_valid_sql_snippet(snippet: str) -> bool:
    if len(snippet) < 20:
        return False
    # Ignore broken fragments such as SELECT ' ... with unmatched quotes.
    if snippet.count("'") % 2 != 0:
        return False
    if snippet.count('"') % 2 != 0:
        return False
    lower = snippet.lower()
    if "select" in lower and "from" not in lower:
        return False
    if "insert" in lower and "into" not in lower:
        return False
    if "update" in lower and " set " not in f" {lower} ":
        return False
    if "delete" in lower and "from" not in lower:
        return False
    if "merge" in lower and "into" not in lower:
        return False
    return True


def extract_class_names(source: str) -> list[str]:
    return dedupe_keep_order(JAVA_CLASS_REGEX.findall(source))


def extract_methods_and_params(source: str) -> tuple[list[str], list[str]]:
    method_names: list[str] = []
    parameter_names: list[str] = []

    for match in JAVA_METHOD_REGEX.finditer(source):
        method_name = match.group(1)
        params_blob = match.group(2) or ""

        if method_name and method_name not in {"if", "for", "while", "switch", "catch"}:
            method_names.append(method_name)

        for raw_param in params_blob.split(","):
            p = raw_param.strip()
            if not p:
                continue
            param_match = JAVA_PARAM_NAME_REGEX.search(p)
            if param_match:
                parameter_names.append(param_match.group(1))

    return dedupe_keep_order(method_names), dedupe_keep_order(parameter_names)


def extract_imports(source: str) -> list[str]:
    return dedupe_keep_order(JAVA_IMPORT_REGEX.findall(source))


def extract_qualified_class_refs(source: str) -> list[str]:
    return dedupe_keep_order(JAVA_QUALIFIED_REF_REGEX.findall(source))


def extract_string_literals(source: str) -> list[str]:
    return dedupe_keep_order([x.strip() for x in JAVA_STRING_LITERAL_REGEX.findall(source) if x.strip()])


def extract_code_keywords(
    source: str,
    class_names: list[str],
    method_names: list[str],
    parameter_names: list[str],
    qualified_class_refs: list[str],
    string_literals: list[str],
) -> list[str]:
    keyword_candidates = [
        "vault",
        "token",
        "secret",
        "auth",
        "password",
        "username",
        "http",
        "https",
        "json",
        "xml",
        "s3",
        "oracle",
        "snowflake",
        "api",
        "rest",
        "jdbc",
        "file",
        "path",
        "response",
        "request",
        "bucket",
        "region",
        "presigned",
        "aws",
        "amazon",
        "credential",
        "url",
    ]

    found: list[str] = []
    blob = " ".join(
        [source]
        + class_names
        + method_names
        + parameter_names
        + qualified_class_refs
        + string_literals
    ).lower()

    for keyword in keyword_candidates:
        if keyword in blob:
            found.append(keyword)

    return dedupe_keep_order(found)


def pick_interesting_text_samples(text_values: list[str]) -> list[str]:
    samples: list[str] = []
    for value in text_values:
        v = value.strip()
        if len(v) < 6:
            continue
        if len(v) > 250:
            continue
        if v.startswith("{") and v.endswith("}"):
            continue
        samples.append(v)
    return dedupe_keep_order(samples)


def dedupe_keep_order(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result