import re
import json
from datetime import datetime

from sqlalchemy import bindparam, case, func, or_, select, text
from sqlalchemy.orm import Session

from models.artifact import Artifact


def create_sample_artifacts(db: Session) -> None:
    existing = db.scalar(select(Artifact).limit(1))
    if existing:
        return

    samples = [
        Artifact(
            artifact_id="job-001",
            artifact_type="job",
            name="LoadCustomerSecrets",
            project_name="CustomerIntegration",
            repo_name="shared-integrations",
            repo_path="C:/talend/shared-integrations",
            file_path="process/customer/LoadCustomerSecrets.item",
            relative_path="process/customer/LoadCustomerSecrets.item",
            summary="Loads customer secrets and uses them in downstream processing.",
            search_text="customer secrets vault token rest processing",
            component_types="tPrejob, tJava, tRESTClient",
        ),
    ]

    db.add_all(samples)
    db.commit()


def get_all_artifacts(db: Session) -> list[Artifact]:
    stmt = select(Artifact).order_by(Artifact.id.asc())
    return list(db.scalars(stmt).all())


def get_artifact_by_id(db: Session, artifact_id: int) -> Artifact | None:
    return db.get(Artifact, artifact_id)


def search_artifacts(
    db: Session,
    query: str = "",
    artifact_type: str = "All",
) -> list[Artifact]:
    stmt = select(Artifact)

    if artifact_type == "Jobs":
        stmt = stmt.where(Artifact.artifact_type == "job")
    elif artifact_type == "Routines":
        stmt = stmt.where(Artifact.artifact_type == "routine")
    elif artifact_type == "Joblets":
        stmt = stmt.where(Artifact.artifact_type == "joblet")

    clean_query = query.strip()
    if clean_query:
        fields = [
            Artifact.name,
            Artifact.summary,
            Artifact.search_text,
            Artifact.embedding_text,
            Artifact.component_types,
            Artifact.job_dependencies,
            Artifact.evidence_json,
            Artifact.file_path,
        ]
        query_terms = expand_search_terms(clean_query)

        if len(clean_query) <= 3:
            regex_parts = [
                rf"(^|[^A-Za-z0-9_]){re.escape(term)}([^A-Za-z0-9_]|$)"
                for term in query_terms
            ]
            stmt = stmt.where(
                or_(
                    *[
                        func.coalesce(field, "").op("~*")(regex)
                        for regex in regex_parts
                        for field in fields
                    ]
                )
            )
        else:
            stmt = stmt.where(
                or_(
                    *[
                        field.ilike(f"%{term}%")
                        for term in query_terms
                        for field in fields
                    ]
                )
            )

    stmt = stmt.order_by(
        case(
            (Artifact.artifact_type == "job", 0),
            (Artifact.artifact_type == "joblet", 1),
            (Artifact.artifact_type == "routine", 2),
            else_=3,
        ),
        Artifact.id.asc(),
    )
    return list(db.scalars(stmt).all())


def expand_search_terms(query: str) -> list[str]:
    terms = [query]
    compact = re.sub(r"[\s_-]+", "", query)
    if compact and compact.lower() != query.lower():
        terms.append(compact)

    lower_query = query.lower()
    lower_compact = compact.lower()

    if lower_compact == "hashicorp":
        terms.extend(["HashiCorp", "hashicorp"])
    elif lower_compact == "hashicorpvault":
        terms.extend(["HashiCorp Vault", "HashiCorp", "hashicorp", "vault"])
    elif "vault" in lower_query:
        terms.extend(["vault", "HashiCorp Vault", "secret management"])

    if lower_query in {"ssh", "sftp"}:
        terms.extend(
            [
                "SFTP",
                "SSH private key",
                "SSH key pair",
                "SSH file transfer",
                "key-pair authentication",
                "private key authentication",
                "Snowflake JWT key-pair authentication",
            ]
        )

    return dedupe_keep_order(terms)


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


def insert_artifacts(db: Session, artifacts: list[dict]) -> tuple[int, int, int]:
    inserted = 0
    updated = 0
    skipped_unchanged = 0

    for item in artifacts:
        existing = (
            db.query(Artifact)
            .filter(
                Artifact.repo_name == item["repo_name"],
                Artifact.project_name == item["project_name"],
                Artifact.relative_path == item["relative_path"],
            )
            .first()
        )

        if existing:
            if artifact_source_unchanged(existing, item):
                skipped_unchanged += 1
                continue
            refresh_existing_artifact_from_scan(existing, item)
            updated += 1
            continue

        artifact = Artifact(**item)
        db.add(artifact)
        inserted += 1

    db.commit()
    return inserted, updated, skipped_unchanged


def artifact_source_unchanged(existing: Artifact, item: dict) -> bool:
    next_hash = item.get("source_hash")
    if next_hash and existing.source_hash:
        return existing.source_hash == next_hash
    return (
        existing.file_path == item.get("file_path")
        and existing.source_modified_at == item.get("source_modified_at")
    )


def refresh_existing_artifact_from_scan(existing: Artifact, item: dict) -> None:
    existing.artifact_id = item.get("artifact_id")
    existing.artifact_type = item["artifact_type"]
    existing.name = item["name"]
    existing.repo_name = item["repo_name"]
    existing.project_name = item.get("project_name")
    existing.repo_path = item["repo_path"]
    existing.file_path = item["file_path"]
    existing.relative_path = item.get("relative_path")
    existing.source_hash = item.get("source_hash")
    existing.source_modified_at = item.get("source_modified_at")

    existing.summary = "Discovered artifact changed; regenerate summaries."
    existing.search_text = item.get("search_text", existing.name.lower())
    existing.component_types = item.get("component_types", "")
    existing.embedding_text = None
    existing.embedding_vector = None
    existing.embedding_hash = None
    existing.embedding_model = None
    existing.functional_hash = None
    existing.connectivity_hash = None
    existing.summary_status = "pending"


def get_artifacts_for_summarization(db: Session) -> list[Artifact]:
    stmt = (
        select(Artifact)
        .where(Artifact.artifact_type.in_(["job", "routine"]))
        .order_by(Artifact.id.asc())
    )
    return list(db.scalars(stmt).all())


def get_routine_artifacts(db: Session) -> list[Artifact]:
    stmt = (
        select(Artifact)
        .where(Artifact.artifact_type == "routine")
        .order_by(Artifact.id.asc())
    )
    return list(db.scalars(stmt).all())


def update_artifact_summary(
    db: Session,
    artifact_id: int,
    summary: str,
    search_text: str,
    component_types: str,
    embedding_text: str,
    functional_hash: str,
    connectivity_hash: str,
    job_dependencies: list[dict] | None = None,
    evidence: dict | None = None,
    summary_status: str = "complete",
) -> None:
    artifact = db.get(Artifact, artifact_id)
    if not artifact:
        return

    embedding_text_changed = (artifact.embedding_text or "") != (embedding_text or "")

    artifact.summary = summary
    artifact.search_text = search_text
    artifact.component_types = component_types
    artifact.embedding_text = embedding_text
    artifact.job_dependencies = json.dumps(job_dependencies or [], separators=(",", ":"))
    next_evidence = evidence or {}
    try:
        existing_evidence = json.loads(artifact.evidence_json or "{}")
    except json.JSONDecodeError:
        existing_evidence = {}
    for preserved_key in ["vulnerability_scan", "studio_patch_info"]:
        if preserved_key in existing_evidence and preserved_key not in next_evidence:
            next_evidence[preserved_key] = existing_evidence[preserved_key]

    artifact.evidence_json = json.dumps(next_evidence, separators=(",", ":"), default=str)
    if embedding_text_changed:
        artifact.embedding_vector = None
        artifact.embedding_hash = None
        artifact.embedding_model = None
    artifact.functional_hash = functional_hash
    artifact.connectivity_hash = connectivity_hash
    artifact.summary_status = summary_status
    artifact.last_summarized_at = datetime.utcnow()
    db.commit()


def update_artifact_evidence(
    db: Session,
    artifact_id: int,
    patch: dict,
) -> None:
    artifact = db.get(Artifact, artifact_id)
    if not artifact:
        return

    try:
        evidence = json.loads(artifact.evidence_json or "{}")
    except json.JSONDecodeError:
        evidence = {}

    evidence.update(patch)
    artifact.evidence_json = json.dumps(evidence, separators=(",", ":"), default=str)
    db.commit()


def find_artifact_by_job_name(
    db: Session,
    repo_name: str,
    project_name: str | None,
    job_name: str,
) -> Artifact | None:
    clean_name = job_name.strip()
    if not clean_name:
        return None

    stmt = select(Artifact).where(
        Artifact.repo_name == repo_name,
        Artifact.artifact_type == "job",
        or_(
            Artifact.name == clean_name,
            Artifact.name == f"{clean_name}_0.1",
            Artifact.name.ilike(f"{clean_name}_%"),
        ),
    )
    if project_name:
        stmt = stmt.where(Artifact.project_name == project_name)

    return db.scalars(stmt.order_by(Artifact.id.asc())).first()


def update_artifact_hashes(
    db: Session,
    artifact_id: int,
    functional_hash: str,
    connectivity_hash: str,
    summary_status: str = "skipped",
) -> None:
    artifact = db.get(Artifact, artifact_id)
    if not artifact:
        return

    artifact.functional_hash = functional_hash
    artifact.connectivity_hash = connectivity_hash
    artifact.summary_status = summary_status
    db.commit()


def update_artifact_embedding(
    db: Session,
    artifact_id: int,
    embedding_vector: str,
    embedding_hash: str,
    embedding_model: str,
) -> None:
    db.execute(
        text(
            "UPDATE artifacts "
            "SET embedding_vector = CAST(:embedding_vector AS vector), "
            "embedding_hash = :embedding_hash, "
            "embedding_model = :embedding_model "
            "WHERE id = :artifact_id"
        ),
        {
            "artifact_id": artifact_id,
            "embedding_vector": embedding_vector,
            "embedding_hash": embedding_hash,
            "embedding_model": embedding_model,
        },
    )
    db.commit()


def search_artifacts_by_pgvector(
    db: Session,
    query_vector: str,
    embedding_model: str,
    artifact_type: str = "All",
    candidate_ids: list[int] | None = None,
    limit: int = 25,
    min_score: float = 0.03,
) -> list[tuple[Artifact, float]]:
    where_clauses = [
        "embedding_vector IS NOT NULL",
        "embedding_model = :embedding_model",
    ]
    params = {
        "query_vector": query_vector,
        "embedding_model": embedding_model,
        "limit": limit,
        "min_score": min_score,
    }

    if artifact_type == "Jobs":
        where_clauses.append("artifact_type = 'job'")
    elif artifact_type == "Routines":
        where_clauses.append("artifact_type = 'routine'")
    elif artifact_type == "Joblets":
        where_clauses.append("artifact_type = 'joblet'")

    if candidate_ids is not None:
        if not candidate_ids:
            return []
        where_clauses.append("id IN :candidate_ids")
        params["candidate_ids"] = candidate_ids

    sql = text(
        "WITH ranked AS ("
        "SELECT id, 1 - (embedding_vector <=> CAST(:query_vector AS vector)) AS score "
        "FROM artifacts "
        f"WHERE {' AND '.join(where_clauses)} "
        "ORDER BY embedding_vector <=> CAST(:query_vector AS vector) "
        "LIMIT :limit"
        ") "
        "SELECT id, score FROM ranked WHERE score >= :min_score "
        "ORDER BY score DESC"
    )

    if candidate_ids is not None:
        sql = sql.bindparams(bindparam("candidate_ids", expanding=True))

    rows = db.execute(sql, params).all()
    ids = [row.id for row in rows]
    if not ids:
        return []

    artifacts = db.query(Artifact).filter(Artifact.id.in_(ids)).all()
    artifacts_by_id = {artifact.id: artifact for artifact in artifacts}
    return [
        (artifacts_by_id[row.id], float(row.score))
        for row in rows
        if row.id in artifacts_by_id
    ]
