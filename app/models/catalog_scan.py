from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.base import Base


class CatalogScan(Base):
    __tablename__ = "catalog_scans"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    input_path: Mapped[str] = mapped_column(Text, nullable=False)
    input_type: Mapped[str] = mapped_column(String(50), nullable=False, default="talend_repo")
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="running")
    scan_hash: Mapped[str] = mapped_column(Text, nullable=False)

    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_message: Mapped[str] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
