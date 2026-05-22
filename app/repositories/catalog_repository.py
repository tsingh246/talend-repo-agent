import json
from datetime import datetime

from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session

from models.artifact import Artifact
from models.catalog_finding import CatalogFinding
from models.catalog_scan import CatalogScan


def create_catalog_scan(db: Session, input_path: str, input_type: str, scan_hash: str) -> CatalogScan:
    scan = CatalogScan(
        input_path=input_path,
        input_type=input_type,
        scan_hash=scan_hash,
        status="running",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def finish_catalog_scan(
    db: Session,
    scan_id: int,
    status: str,
    finding_count: int,
    error_message: str | None = None,
) -> None:
    scan = db.get(CatalogScan, scan_id)
    if not scan:
        return
    scan.status = status
    scan.finding_count = finding_count
    scan.error_message = error_message
    scan.finished_at = datetime.utcnow()
    db.commit()


def latest_catalog_scan(db: Session, input_path: str) -> CatalogScan | None:
    stmt = (
        select(CatalogScan)
        .where(CatalogScan.input_path == input_path)
        .order_by(CatalogScan.id.desc())
        .limit(1)
    )
    return db.scalars(stmt).first()


def replace_catalog_findings(db: Session, scan_id: int, findings: list[dict]) -> int:
    db.execute(delete(CatalogFinding))
    for finding in findings:
        db.add(CatalogFinding(scan_id=scan_id, **finding))
    db.commit()
    return len(findings)


def search_catalog_findings(
    db: Session,
    query: str = "",
    pii_category: str = "",
    source_type: str = "",
    project_name: str = "",
    search_mode: str = "Text + Meaning",
) -> list[CatalogFinding]:
    stmt = select(CatalogFinding)
    if query.strip():
        terms = expand_catalog_query(query)
        fields = catalog_search_fields(search_mode)
        stmt = stmt.where(or_(*[field.ilike(f"%{term}%") for term in terms for field in fields]))
    if pii_category:
        stmt = stmt.where(CatalogFinding.pii_category == pii_category)
    if source_type:
        stmt = stmt.where(CatalogFinding.source_type == source_type)
    if project_name:
        stmt = stmt.where(CatalogFinding.project_name == project_name)
    stmt = stmt.order_by(CatalogFinding.confidence.desc(), CatalogFinding.job_name.asc()).limit(500)
    return list(db.scalars(stmt).all())


def catalog_search_fields(search_mode: str) -> list:
    meaning_fields = [
        CatalogFinding.semantic_labels_json,
        CatalogFinding.pii_category,
    ]
    text_fields = [
        CatalogFinding.field_name,
        CatalogFinding.normalized_field_name,
        CatalogFinding.evidence_text,
        CatalogFinding.table_name,
        CatalogFinding.component_name,
        CatalogFinding.component_type,
        CatalogFinding.job_name,
    ]
    if search_mode == "Meaning only":
        return meaning_fields
    if search_mode == "Text only":
        return text_fields
    return text_fields + meaning_fields


def get_catalog_findings(db: Session) -> list[CatalogFinding]:
    stmt = select(CatalogFinding).order_by(CatalogFinding.project_name.asc(), CatalogFinding.job_name.asc())
    return list(db.scalars(stmt).all())


def get_catalog_filter_options(db: Session) -> dict:
    findings = get_catalog_findings(db)
    return {
        "projects": sorted({f.project_name for f in findings if f.project_name}),
        "pii_categories": sorted({f.pii_category for f in findings if f.pii_category}),
        "source_types": sorted({f.source_type for f in findings if f.source_type}),
    }


def expand_catalog_query(query: str) -> list[str]:
    normalized = normalize_query(query)
    terms = [query, normalized]
    alias_groups = {
        "ssn": ["social security", "social security number", "tax id", "taxpayer", "tin"],
        "social security number": ["ssn", "tax id", "taxpayer", "tin"],
        "dob": ["date of birth", "birth date", "birth_dt"],
        "email": ["e-mail", "email address"],
        "phone": ["telephone", "mobile", "cell"],
        "jwt": ["token", "credential"],
    }
    for key, aliases in alias_groups.items():
        if key in normalized:
            terms.extend(aliases)
    return dedupe_keep_order([term for term in terms if term])


def normalize_query(value: str) -> str:
    return " ".join(str(value or "").lower().replace("_", " ").replace("-", " ").split())


def catalog_finding_to_dict(finding: CatalogFinding) -> dict:
    return {
        "project": finding.project_name or "",
        "job": finding.job_name or "",
        "artifact_type": finding.artifact_type or "",
        "component": finding.component_name or "",
        "component_type": finding.component_type or "",
        "field": finding.field_name,
        "meaning": ", ".join(parse_json_list(finding.semantic_labels_json)),
        "pii_category": finding.pii_category or "",
        "source_type": finding.source_type,
        "direction": finding.direction,
        "table": finding.table_name or "",
        "confidence": finding.confidence,
        "evidence": finding.evidence_text or "",
        "file_path": finding.file_path,
    }


def artifact_lookup(db: Session) -> dict[str, Artifact]:
    return {
        artifact.file_path.replace("\\", "/").lower(): artifact
        for artifact in db.scalars(select(Artifact)).all()
    }


def parse_json_list(value: str | None) -> list[str]:
    try:
        parsed = json.loads(value or "[]")
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


def dedupe_keep_order(values: list[str]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result
