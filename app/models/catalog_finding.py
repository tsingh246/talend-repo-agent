from datetime import datetime

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.base import Base


class CatalogFinding(Base):
    __tablename__ = "catalog_findings"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    scan_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("catalog_scans.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    artifact_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("artifacts.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    repo_name: Mapped[str] = mapped_column(String(255), nullable=True, index=True)
    project_name: Mapped[str] = mapped_column(String(255), nullable=True, index=True)
    job_name: Mapped[str] = mapped_column(String(255), nullable=True, index=True)
    artifact_type: Mapped[str] = mapped_column(String(50), nullable=True)
    file_path: Mapped[str] = mapped_column(Text, nullable=False)

    component_name: Mapped[str] = mapped_column(String(255), nullable=True, index=True)
    component_type: Mapped[str] = mapped_column(String(255), nullable=True, index=True)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    direction: Mapped[str] = mapped_column(String(50), nullable=False, default="unknown")

    field_name: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    normalized_field_name: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    semantic_labels_json: Mapped[str] = mapped_column(Text, nullable=True)
    pii_category: Mapped[str] = mapped_column(String(100), nullable=True, index=True)

    table_name: Mapped[str] = mapped_column(String(500), nullable=True, index=True)
    evidence_text: Mapped[str] = mapped_column(Text, nullable=True)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.8)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
