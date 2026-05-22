from __future__ import annotations
import html
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any


URL_REGEX = re.compile(r"https?://[^\s\"'<>\\&]+", re.IGNORECASE)
CONTEXT_REGEX = re.compile(r"context\.[A-Za-z0-9_]+")
SQL_REGEX = re.compile(r"\b(select|insert|update|delete|merge)\b", re.IGNORECASE)

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

SQL_PROPERTY_KEYS = {
    "query",
    "sql",
    "dbquery",
    "elt_query",
    "querystore",
}

TABLE_PROPERTY_KEYS = {
    "table",
    "table_name",
    "tablename",
}


def parse_item_file(file_path: str, artifact_type: str) -> dict[str, Any]:
    path = Path(file_path)

    empty_result = {
        "component_types": [],
        "labels": [],
        "urls": [],
        "context_refs": [],
        "sql_snippets": [],
        "sql_evidence": [],
        "text_samples": [],
        "code_snippets": [],
        "method_names": [],
        "imports": [],
        "string_literals": [],
        "code_keywords": [],
        "config_signals": [],
        "auth_signals": [],
        "class_names": [],
        "parameter_names": [],
        "qualified_class_refs": [],
        "job_dependencies": [],
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
    sql_evidence: list[dict] = []
    job_dependencies: list[dict] = []

    root = None
    try:
        tree = ET.parse(path)
        root = tree.getroot()
    except Exception:
        root = None

    if root is not None:
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

        sql_evidence = extract_sql_evidence_from_xml(root)
        job_dependencies = extract_t_run_job_dependencies(root)

    # Always inspect raw text
    if raw_text:
        all_text_values.append(raw_text)

        # For routines, raw text is source of truth even if XML parsing fails
        if artifact_type == "routine":
            code_snippets.append(clean_snippet(raw_text, max_len=3000))
        elif looks_like_code(raw_text):
            code_snippets.append(clean_snippet(raw_text, max_len=3000))

    all_text_values = dedupe_keep_order([x for x in all_text_values if x])
    component_types = dedupe_keep_order(component_types)
    labels = dedupe_keep_order(labels)
    code_snippets = dedupe_keep_order(code_snippets)

    urls = extract_urls(all_text_values)
    context_refs = extract_context_refs(all_text_values)
    sql_snippets = extract_sql_snippets(all_text_values)
    text_samples = pick_interesting_text_samples(all_text_values)
    config_signals = extract_config_signals(all_text_values + code_snippets + urls + context_refs)
    auth_signals = extract_auth_signals(all_text_values + code_snippets + urls + context_refs)

    method_names: list[str] = []
    imports: list[str] = []
    string_literals: list[str] = []
    code_keywords: list[str] = []
    class_names: list[str] = []
    parameter_names: list[str] = []
    qualified_class_refs: list[str] = []

    source_for_keywords = redact_sensitive_values(
        "\n".join(all_text_values + code_snippets + config_signals + auth_signals)
    )

    if artifact_type == "routine":
        routine_source = source_for_keywords

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
    else:
        code_keywords = extract_code_keywords(
            source_for_keywords,
            class_names=[],
            method_names=[],
            parameter_names=[],
            qualified_class_refs=[],
            string_literals=[],
        )

    return {
        "component_types": component_types[:30],
        "labels": labels[:30],
        "urls": urls[:20],
        "context_refs": context_refs[:30],
        "sql_snippets": sql_snippets[:10],
        "sql_evidence": sql_evidence[:20],
        "text_samples": text_samples[:20],
        "code_snippets": code_snippets[:10],
        "method_names": method_names[:20],
        "imports": imports[:20],
        "string_literals": string_literals[:20],
        "code_keywords": code_keywords[:30],
        "config_signals": config_signals[:30],
        "auth_signals": auth_signals[:30],
        "class_names": class_names[:10],
        "parameter_names": parameter_names[:30],
        "qualified_class_refs": qualified_class_refs[:30],
        "job_dependencies": job_dependencies[:50],
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
        ";",
    ]
    return any(token in sample for token in indicators)


def clean_snippet(text: str, max_len: int = 500) -> str:
    cleaned = " ".join(redact_sensitive_values(text).strip().split())
    return cleaned[:max_len]


def extract_urls(text_values: list[str]) -> list[str]:
    ignored_domains = [
        "www.omg.org",
        "www.w3.org",
        "www.talend.org",
    ]

    results: list[str] = []

    for value in text_values:
        for url in URL_REGEX.findall(value):
            cleaned_url = clean_extracted_url(url)
            lower = cleaned_url.lower()
            if any(domain in lower for domain in ignored_domains):
                continue
            results.append(cleaned_url)

    return dedupe_keep_order(results)


def clean_extracted_url(url: str) -> str:
    cleaned = html.unescape(url).strip()
    for marker in ['"', "'", "<", ">", "\\", "&quot;", "&#xA;"]:
        if marker in cleaned:
            cleaned = cleaned.split(marker, 1)[0]
    return cleaned.rstrip(".,;)")

def extract_context_refs(text_values: list[str]) -> list[str]:
    results: list[str] = []
    for value in text_values:
        results.extend(CONTEXT_REGEX.findall(value))
    return dedupe_keep_order(results)


def extract_sql_snippets(text_values: list[str]) -> list[str]:
    results: list[str] = []
    for value in text_values:
        if SQL_REGEX.search(value):
            results.append(clean_sql(value, max_len=400))
    return dedupe_keep_order(results)


def extract_sql_evidence_from_xml(root) -> list[dict]:
    sql_items: list[dict] = []

    for elem in root.iter():
        elem_attrs = {k.lower(): v for k, v in elem.attrib.items()}

        component_name = (
            elem_attrs.get("componentname")
            or elem_attrs.get("component_name")
            or elem_attrs.get("name")
            or ""
        )

        for key, value in elem.attrib.items():
            key_l = key.lower()

            if not isinstance(value, str):
                continue

            clean_value = value.strip()
            if not clean_value:
                continue

            if key_l in SQL_PROPERTY_KEYS or looks_like_sql(clean_value):
                sql_items.append(
                    {
                        "component": component_name,
                        "property": key,
                        "operation": detect_sql_operation(clean_value),
                        "tables": extract_sql_tables(clean_value),
                        "sql": clean_sql(clean_value),
                        "signature": build_sql_signature(clean_value),
                    }
                )

    return dedupe_sql_evidence(sql_items)


def extract_t_run_job_dependencies(root) -> list[dict]:
    dependencies: list[dict] = []

    for node in root.iter():
        if node.attrib.get("componentName") != "tRunJob":
            continue

        params = {}
        for child in node:
            if child.tag.split("}")[-1] != "elementParameter":
                continue
            name = child.attrib.get("name")
            if name:
                params[name] = child.attrib.get("value", "")

        technical_ref = params.get("PROCESS:PROCESS_TYPE_PROCESS", "")
        target_project = ""
        target_id = technical_ref
        if ":" in technical_ref:
            target_project, target_id = technical_ref.split(":", 1)

        dependency = {
            "component": params.get("UNIQUE_NAME", ""),
            "target_job": params.get("PROCESS", ""),
            "target_project": target_project,
            "target_id": target_id,
            "context": params.get("PROCESS:PROCESS_TYPE_CONTEXT", ""),
            "version": params.get("PROCESS:PROCESS_TYPE_VERSION", ""),
            "dynamic": params.get("USE_DYNAMIC_JOB", ""),
            "independent_process": params.get("USE_INDEPENDENT_PROCESS", ""),
        }

        if dependency["target_job"] or dependency["target_id"]:
            dependencies.append(dependency)

    return dedupe_dependencies(dependencies)


def dedupe_dependencies(items: list[dict]) -> list[dict]:
    seen = set()
    result = []
    for item in items:
        key = (
            item.get("component", ""),
            item.get("target_job", ""),
            item.get("target_project", ""),
            item.get("target_id", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result

def looks_like_sql(value: str) -> bool:
    v = clean_sql(value).lower().strip()

    return (
        v.startswith("select ")
        or v.startswith("insert ")
        or v.startswith("update ")
        or v.startswith("delete ")
        or v.startswith("merge ")
        or " from " in v
        or " join " in v
        or " where " in v
        or " group by " in v
    )


def detect_sql_operation(sql: str) -> str:
    s = clean_sql(sql).lower().strip()

    for op in ["select", "insert", "update", "delete", "merge"]:
        if s.startswith(op):
            return op.upper()

    return "SQL"

def build_database_keywords(component_types: list[str]) -> list[str]:
    db_tech = detect_database_technology(component_types)
    if not db_tech:
        return []

    return [
        f"database_type:{db_tech}",
        db_tech,
        db_tech.lower(),
    ]

def clean_sql(sql: str, max_len: int = 5000) -> str:
    decoded = html.unescape(sql).strip()

    # Remove wrapping quotes from Talend XML values
    if len(decoded) >= 2 and decoded[0] == '"' and decoded[-1] == '"':
        decoded = decoded[1:-1]

    # 🔥 Remove SQL comments

    # Remove multi-line comments /* ... */
    decoded = re.sub(r"/\*.*?\*/", " ", decoded, flags=re.DOTALL)

    # Remove single-line comments -- ...
    decoded = re.sub(r"--.*?(?=\n|$)", " ", decoded)

    # Normalize whitespace
    cleaned = " ".join(
        decoded.replace("\r", " ").replace("\n", " ").replace("\t", " ").split()
    )
    cleaned = redact_sensitive_values(cleaned)

    return cleaned[:max_len]


def redact_sensitive_values(text: str) -> str:
    redacted = re.sub(
        r"enc:system\.encryption\.key\.v1:[A-Za-z0-9+/=]+",
        "enc:system.encryption.key.v1:[REDACTED]",
        text,
        flags=re.IGNORECASE,
    )
    redacted = re.sub(
        r"((?:password|pwd|secret|token|private_key_file_pwd|securitykey)\s*[=:]\s*)[^&\s\"']+",
        r"\1[REDACTED]",
        redacted,
        flags=re.IGNORECASE,
    )
    return redacted
def build_sql_signature(sql: str, max_len: int = 500) -> str:
    cleaned = clean_sql(sql).lower()
    cleaned = re.sub(r"[^a-z0-9_.$]+", " ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:max_len]

def extract_sql_tables(sql: str) -> list[str]:
    cleaned = clean_sql(sql)

    table_patterns = [
        r"\bfrom\s+([A-Za-z0-9_.$]+)",
        r"\bjoin\s+([A-Za-z0-9_.$]+)",
        r"\binto\s+([A-Za-z0-9_.$]+)",
        r"\bupdate\s+([A-Za-z0-9_.$]+)",
    ]

    tables: list[str] = []
    for pattern in table_patterns:
        for match in re.finditer(pattern, cleaned, re.IGNORECASE):
            tables.append(match.group(1))

    return dedupe_keep_order(tables)


def dedupe_sql_evidence(items: list[dict]) -> list[dict]:
    seen = set()
    result = []

    for item in items:
        signature = item.get("signature", "")
        if not signature:
            continue

        if signature in seen:
            continue

        seen.add(signature)
        result.append(item)

    return result


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
    return dedupe_keep_order(
        [x.strip() for x in JAVA_STRING_LITERAL_REGEX.findall(source) if x.strip()]
    )


def extract_code_keywords(
    source: str,
    class_names: list[str],
    method_names: list[str],
    parameter_names: list[str],
    qualified_class_refs: list[str],
    string_literals: list[str],
) -> list[str]:
    keyword_candidates = [
        "hashicorp",
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
        "sftp",
        "ssh",
        "private_key",
        "privatekey",
        "keypair",
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


def extract_config_signals(text_values: list[str]) -> list[str]:
    blob = " ".join(redact_sensitive_values(str(value)) for value in text_values).lower()
    signals: list[str] = []

    if "hashicorp" in blob or "vault" in blob or "bettercloud.vault" in blob:
        signals.extend(
            [
                "HashiCorp Vault",
                "vault",
                "hashicorp",
                "secret management",
            ]
        )

    if "vault_aws_role" in blob or "talendvaultauthfactory" in blob or "authenticatevault" in blob:
        signals.append("Vault AWS IAM authentication")

    if "sftp" in blob:
        signals.extend(["SFTP", "SSH file transfer"])

    if "tssh" in blob:
        signals.append("Talend SSH component")

    if (
        "privatekey" in blob
        or "private_key_file" in blob
        or "private_key_base64" in blob
        or "/.ssh/" in blob
        or "ssh-rsa" in blob
        or "openssh" in blob
    ):
        signals.extend(["SSH private key", "SSH key pair", "key-pair authentication"])

    if "snowflake_jwt" in blob or ("snowflake" in blob and "private_key" in blob):
        signals.extend(
            [
                "Snowflake JWT key-pair authentication",
                "snowflake key pair",
                "snowflake private key",
            ]
        )

    if "oauth" in blob:
        signals.append("OAuth authentication")
    if "basic" in blob and ("auth" in blob or "login" in blob):
        signals.append("Basic authentication")

    return dedupe_keep_order(signals)


def extract_auth_signals(text_values: list[str]) -> list[str]:
    blob = " ".join(redact_sensitive_values(str(value)) for value in text_values).lower()
    signals: list[str] = []

    auth_map = [
        ("HashiCorp Vault authentication", ["hashicorp", "vault"]),
        ("Vault AWS IAM authentication", ["vault_aws_role", "authenticatevault"]),
        ("SFTP/SSH authentication", ["sftp", "ssh-rsa", "openssh", "/.ssh/"]),
        ("Private key authentication", ["privatekey", "private_key_file", "private_key_base64"]),
        ("Snowflake JWT key-pair authentication", ["snowflake_jwt"]),
        ("OAuth authentication", ["oauth"]),
        ("Token authentication", ["token"]),
    ]

    for label, markers in auth_map:
        if any(marker in blob for marker in markers):
            signals.append(label)

    return dedupe_keep_order(signals)


def pick_interesting_text_samples(text_values: list[str]) -> list[str]:
    samples: list[str] = []
    for value in text_values:
        v = redact_sensitive_values(value).strip()

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
