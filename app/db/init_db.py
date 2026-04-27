from db.base import Base
from db.session import engine

# Import models so SQLAlchemy knows about them
from models.artifact import Artifact  # noqa: F401


def init_db() -> None:
    Base.metadata.create_all(bind=engine)