from __future__ import annotations

import hashlib
import html
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path


PII_TERMS = {
    "Social Security Number": ["ssn", "social security", "social_security", "soc sec"],
    "Date of Birth": ["dob", "date of birth", "birth date", "birth_dt"],
    "Email Address": ["email", "e-mail", "mail address"],
    "Phone Number": ["phone", "telephone", "mobile", "cell"],
    "Tax Identifier": ["tax id", "tax_id", "tin", "taxpayer"],
    "Address": ["address", "addr", "street", "postal", "zipcode", "zip"],
    "Account Number": ["account number", "acct", "account_no", "account_num"],
    "Credential / Token": ["token", "jwt", "password", "secret", "private key"],
}

SQL_TABLE_REGEX = re.compile(
    r"\b(?:from|join|into|update)\s+([A-Za-z_][A-Za-z0-9_$#]*(?:\.[A-Za-z_][A-Za-z0-9_$#]*)?)",
    re.IGNORECASE,
)
SQL_COLUMN_REGEX = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")


@dataclass
class CatalogFindingResult:
    project_name: str
    repo_name: str
    job_name: str
    artifact_type: str
    file_path: str
    component_name: str
    component_type: str
    source_type: str
    direction: str
    field_name: str
    normalized_field_name: str
    semantic_labels: list[str] = field(default_factory=list)
    pii_category: str = ""
    table_name: str = ""
    evidence_text: str = ""
    confidence: float = 0.8


@dataclass
class CatalogScanResult:
    input_path: str
    input_type: str
    scan_hash: str
    findings: list[CatalogFindingResult]


def run_catalog_scan(input_path: str | Path = "data/repos") -> CatalogScanResult:
    root = Path(input_path)
    findings = []
    for item_path in root.rglob("*.item"):
        artifact_type = classify_artifact(item_path)
        if not artifact_type:
            continue
        findings.extend(scan_item(item_path, root, artifact_type))

    return CatalogScanResult(
        input_path=str(root),
        input_type="talend_repo",
        scan_hash=compute_scan_hash(root),
        findings=dedupe_findings(findings),
    )


def scan_item(item_path: Path, root: Path, artifact_type: str) -> list[CatalogFindingResult]:
    repo_name, project_name = infer_repo_project(item_path, root)
    job_name = item_path.stem
    try:
        xml_root = ET.parse(item_path).getroot()
    except Exception:
        return []

    findings = []
    for node in iter_by_local_name(xml_root, "node"):
        component_type = node.attrib.get("componentName", "")
        component_name = find_component_name(node) or component_type
        findings.extend(
            scan_node_columns(
                node,
                repo_name,
                project_name,
                job_name,
                artifact_type,
                str(item_path),
                component_name,
                component_type,
            )
        )
        findings.extend(
            scan_node_parameters(
                node,
                repo_name,
                project_name,
                job_name,
                artifact_type,
                str(item_path),
                component_name,
                component_type,
            )
        )

    return findings


def scan_node_columns(
    node,
    repo_name: str,
    project_name: str,
    job_name: str,
    artifact_type: str,
    file_path: str,
    component_name: str,
    component_type: str,
) -> list[CatalogFindingResult]:
    findings = []
    for metadata in iter_by_local_name(node, "metadata"):
        connector = metadata.attrib.get("connector", "")
        direction = infer_direction(connector, component_type)
        for column in iter_by_local_name(metadata, "column"):
            field_name = column.attrib.get("name", "")
            if not useful_field_name(field_name):
                continue
            findings.append(
                build_finding(
                    repo_name,
                    project_name,
                    job_name,
                    artifact_type,
                    file_path,
                    component_name,
                    component_type,
                    source_type="schema",
                    direction=direction,
                    field_name=field_name,
                    evidence_text=f"{component_name} {connector} column {field_name}",
                    confidence=0.95,
                )
            )
    return findings


def scan_node_parameters(
    node,
    repo_name: str,
    project_name: str,
    job_name: str,
    artifact_type: str,
    file_path: str,
    component_name: str,
    component_type: str,
) -> list[CatalogFindingResult]:
    findings = []
    for parameter in iter_by_local_name(node, "elementParameter"):
        name = parameter.attrib.get("name", "")
        value = clean_value(parameter.attrib.get("value", ""))
        if not value:
            continue

        lower_name = name.lower()
        if any(token in lower_name for token in ["query", "sql"]):
            findings.extend(
                build_sql_findings(
                    value,
                    repo_name,
                    project_name,
                    job_name,
                    artifact_type,
                    file_path,
                    component_name,
                    component_type,
                )
            )
        elif name.startswith("PROPERTY:") or "SCHEMA" in name or "COLUMN" in name:
            for token in extract_identifier_tokens(value):
                findings.append(
                    build_finding(
                        repo_name,
                        project_name,
                        job_name,
                        artifact_type,
                        file_path,
                        component_name,
                        component_type,
                        source_type="component_config",
                        direction="unknown",
                        field_name=token,
                        evidence_text=f"{name}: {value[:250]}",
                        confidence=0.55,
                    )
                )
        elif "context." in value:
            for token in re.findall(r"context\.([A-Za-z0-9_]+)", value):
                findings.append(
                    build_finding(
                        repo_name,
                        project_name,
                        job_name,
                        artifact_type,
                        file_path,
                        component_name,
                        component_type,
                        source_type="context",
                        direction="unknown",
                        field_name=token,
                        evidence_text=f"{name}: {value[:250]}",
                        confidence=0.75,
                    )
                )

    return findings


def build_sql_findings(
    sql: str,
    repo_name: str,
    project_name: str,
    job_name: str,
    artifact_type: str,
    file_path: str,
    component_name: str,
    component_type: str,
) -> list[CatalogFindingResult]:
    tables = SQL_TABLE_REGEX.findall(sql)
    findings = []
    for table in tables:
        findings.append(
            build_finding(
                repo_name,
                project_name,
                job_name,
                artifact_type,
                file_path,
                component_name,
                component_type,
                source_type="sql_table",
                direction=infer_direction("", component_type),
                field_name=table,
                table_name=table,
                evidence_text=sql[:500],
                confidence=0.85,
            )
        )

    for token in extract_identifier_tokens(sql):
        if token.lower() in SQL_STOPWORDS or "." in token:
            continue
        findings.append(
            build_finding(
                repo_name,
                project_name,
                job_name,
                artifact_type,
                file_path,
                component_name,
                component_type,
                source_type="sql_column",
                direction=infer_direction("", component_type),
                field_name=token,
                table_name=tables[0] if tables else "",
                evidence_text=sql[:500],
                confidence=0.45,
            )
        )
    return findings


SQL_STOPWORDS = {
    "select", "from", "where", "and", "or", "join", "on", "inner", "left", "right",
    "insert", "update", "delete", "merge", "into", "values", "set", "case", "when",
    "then", "else", "end", "as", "is", "null", "not", "distinct", "group", "order",
    "by", "having", "count", "sum", "min", "max", "avg", "int", "string", "long",
    "double", "float", "boolean", "globalmap", "globalMap", "get", "put", "true",
    "false", "system", "context", "integer",
}


def build_finding(
    repo_name: str,
    project_name: str,
    job_name: str,
    artifact_type: str,
    file_path: str,
    component_name: str,
    component_type: str,
    source_type: str,
    direction: str,
    field_name: str,
    evidence_text: str,
    confidence: float,
    table_name: str = "",
) -> CatalogFindingResult:
    normalized = normalize_field_name(field_name)
    semantic_labels, pii_category = classify_semantic_labels(normalized)
    return CatalogFindingResult(
        repo_name=repo_name,
        project_name=project_name,
        job_name=job_name,
        artifact_type=artifact_type,
        file_path=file_path,
        component_name=component_name,
        component_type=component_type,
        source_type=source_type,
        direction=direction,
        field_name=field_name,
        normalized_field_name=normalized,
        semantic_labels=semantic_labels,
        pii_category=pii_category,
        table_name=table_name,
        evidence_text=evidence_text,
        confidence=confidence,
    )


def classify_semantic_labels(normalized: str) -> tuple[list[str], str]:
    labels = []
    for label, aliases in PII_TERMS.items():
        if any(alias in normalized for alias in aliases):
            labels.append(label)
    return labels, labels[0] if labels else ""


def normalize_field_name(value: str) -> str:
    value = re.sub(r"([a-z])([A-Z])", r"\1 \2", value)
    value = re.sub(r"[^A-Za-z0-9]+", " ", value)
    return " ".join(value.lower().split())


def extract_identifier_tokens(value: str) -> list[str]:
    return [
        token
        for token in SQL_COLUMN_REGEX.findall(value)
        if useful_field_name(token)
    ][:80]


def useful_field_name(value: str) -> bool:
    if not value or len(value) < 2:
        return False
    if value.lower() in SQL_STOPWORDS:
        return False
    return bool(re.search(r"[A-Za-z]", value))


def find_component_name(node) -> str:
    for parameter in iter_by_local_name(node, "elementParameter"):
        if parameter.attrib.get("name") == "UNIQUE_NAME":
            return clean_value(parameter.attrib.get("value", ""))
    return ""


def infer_direction(connector: str, component_type: str) -> str:
    text = f"{connector} {component_type}".lower()
    if "output" in text or component_type.lower().endswith("output"):
        return "output"
    if "input" in text or component_type.lower().endswith("input"):
        return "input"
    if "reject" in text:
        return "reject"
    if "map" in text or "java" in text:
        return "transform"
    return "unknown"


def clean_value(value: str) -> str:
    return html.unescape(str(value or "")).strip().strip('"')


def iter_by_local_name(root, local_name: str):
    for elem in root.iter():
        if elem.tag.rsplit("}", 1)[-1] == local_name:
            yield elem


def infer_repo_project(item_path: Path, root: Path) -> tuple[str, str]:
    try:
        parts = item_path.relative_to(root).parts
    except ValueError:
        return "", ""
    if parts and parts[0].lower() in {"process", "code", "metadata", "context"}:
        return root.parent.name, root.name
    if len(parts) >= 2:
        return parts[0], parts[1]
    return "", ""


def classify_artifact(item_path: Path) -> str:
    parts = [part.lower() for part in item_path.parts]
    if "process" in parts:
        return "job"
    if "routines" in parts:
        return "routine"
    return ""


def compute_scan_hash(root: Path) -> str:
    hasher = hashlib.sha256()
    for path in sorted(root.rglob("*.item")):
        try:
            hasher.update(str(path.relative_to(root)).encode("utf-8"))
            hasher.update(path.read_bytes())
        except OSError:
            continue
    return hasher.hexdigest()


def dedupe_findings(findings: list[CatalogFindingResult]) -> list[CatalogFindingResult]:
    seen = set()
    result = []
    for finding in findings:
        key = json.dumps(finding.__dict__, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result
