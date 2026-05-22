from datetime import datetime

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.base import Base

try:
    from pgvector.sqlalchemy import Vector
except Exception:
    Vector = None

EMBEDDING_DIMENSION = 384


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    artifact_id: Mapped[str] = mapped_column(String(255), unique=False, nullable=True)
    artifact_type: Mapped[str] = mapped_column(String(50), nullable=False)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    project_name: Mapped[str] = mapped_column(String(255), nullable=True)
    repo_name: Mapped[str] = mapped_column(String(255), nullable=False)
    repo_path: Mapped[str] = mapped_column(Text, nullable=False)
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    relative_path: Mapped[str] = mapped_column(Text, nullable=True)
    source_hash: Mapped[str] = mapped_column(Text, nullable=True)
    source_modified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    summary: Mapped[str] = mapped_column(Text, nullable=True)
    search_text: Mapped[str] = mapped_column(Text, nullable=True)
    embedding_text: Mapped[str] = mapped_column(Text, nullable=True)
    embedding_vector: Mapped[list[float]] = mapped_column(
        Vector(EMBEDDING_DIMENSION) if Vector else Text,
        nullable=True,
    )
    embedding_hash: Mapped[str] = mapped_column(Text, nullable=True)
    embedding_model: Mapped[str] = mapped_column(String(255), nullable=True)
    component_types: Mapped[str] = mapped_column(Text, nullable=True)
    job_dependencies: Mapped[str] = mapped_column(Text, nullable=True)
    evidence_json: Mapped[str] = mapped_column(Text, nullable=True)
    functional_hash: Mapped[str] = mapped_column(Text, nullable=True)
    connectivity_hash: Mapped[str] = mapped_column(Text, nullable=True)
    summary_status: Mapped[str] = mapped_column(String(50), nullable=False, default="pending")
    last_summarized_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
