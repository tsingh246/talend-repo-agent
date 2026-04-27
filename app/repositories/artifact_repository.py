from sqlalchemy import select
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


def insert_artifacts(db: Session, artifacts: list[dict]) -> None:
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
            continue

        artifact = Artifact(**item)
        db.add(artifact)

    db.commit()


def get_artifacts_for_summarization(db: Session) -> list[Artifact]:
    stmt = (
        select(Artifact)
        .where(Artifact.artifact_type.in_(["job", "routine"]))
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
) -> None:
    artifact = db.get(Artifact, artifact_id)
    if not artifact:
        return

    artifact.summary = summary
    artifact.search_text = search_text
    artifact.component_types = component_types
    artifact.embedding_text = embedding_text
    db.commit()