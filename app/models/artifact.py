from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db.base import Base


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

    summary: Mapped[str] = mapped_column(Text, nullable=True)
    search_text: Mapped[str] = mapped_column(Text, nullable=True)
    component_types: Mapped[str] = mapped_column(Text, nullable=True)