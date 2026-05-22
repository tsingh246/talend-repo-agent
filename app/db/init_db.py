from db.base import Base
from db.session import engine
from sqlalchemy import text

# Import models so SQLAlchemy knows about them
from models.artifact import EMBEDDING_DIMENSION, Artifact  # noqa: F401
from models.catalog_finding import CatalogFinding  # noqa: F401
from models.catalog_scan import CatalogScan  # noqa: F401
from models.vulnerability_finding import VulnerabilityFinding  # noqa: F401
from models.vulnerability_scan import VulnerabilityScan  # noqa: F401


def init_db() -> None:
    ensure_pgvector_extension()
    Base.metadata.create_all(bind=engine)
    ensure_artifact_change_detection_columns()
    ensure_vulnerability_columns()
    ensure_pgvector_index()


def ensure_pgvector_extension() -> None:
    with engine.begin() as connection:
        connection.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))


def ensure_artifact_change_detection_columns() -> None:
    column_types = get_artifact_column_types()
    if not column_types:
        return

    columns = set(column_types)
    statements = []

    if "functional_hash" not in columns:
        statements.append("ALTER TABLE artifacts ADD COLUMN functional_hash TEXT")
    if "connectivity_hash" not in columns:
        statements.append("ALTER TABLE artifacts ADD COLUMN connectivity_hash TEXT")
    if "summary_status" not in columns:
        statements.append(
            "ALTER TABLE artifacts ADD COLUMN summary_status VARCHAR(50) DEFAULT 'pending' NOT NULL"
        )
    if "last_summarized_at" not in columns:
        statements.append("ALTER TABLE artifacts ADD COLUMN last_summarized_at TIMESTAMP")
    if "embedding_vector" not in columns:
        statements.append(
            f"ALTER TABLE artifacts ADD COLUMN embedding_vector vector({EMBEDDING_DIMENSION})"
        )
    elif "vector" not in column_types.get("embedding_vector", ""):
        statements.append(
            "ALTER TABLE artifacts ALTER COLUMN embedding_vector "
            f"TYPE vector({EMBEDDING_DIMENSION}) USING NULL::vector({EMBEDDING_DIMENSION})"
        )
    if "embedding_hash" not in columns:
        statements.append("ALTER TABLE artifacts ADD COLUMN embedding_hash TEXT")
    if "embedding_model" not in columns:
        statements.append("ALTER TABLE artifacts ADD COLUMN embedding_model VARCHAR(255)")
    if "job_dependencies" not in columns:
        statements.append("ALTER TABLE artifacts ADD COLUMN job_dependencies TEXT")
    if "evidence_json" not in columns:
        statements.append("ALTER TABLE artifacts ADD COLUMN evidence_json TEXT")

    if not statements:
        return

    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def ensure_vulnerability_columns() -> None:
    finding_column_types = get_table_column_types("vulnerability_findings")
    if finding_column_types:
        columns = set(finding_column_types)
        statements = []
        if "scan_id" not in columns:
            statements.append("ALTER TABLE vulnerability_findings ADD COLUMN scan_id INTEGER")
        if "input_type" not in columns:
            statements.append(
                "ALTER TABLE vulnerability_findings ADD COLUMN input_type VARCHAR(50) DEFAULT 'talend_repo' NOT NULL"
            )
        if "source_jar" not in columns:
            statements.append("ALTER TABLE vulnerability_findings ADD COLUMN source_jar TEXT")
        if statements:
            with engine.begin() as connection:
                for statement in statements:
                    connection.execute(text(statement))

    catalog_column_types = get_table_column_types("catalog_findings")
    if catalog_column_types:
        columns = set(catalog_column_types)
        statements = []
        if "scan_id" not in columns:
            statements.append("ALTER TABLE catalog_findings ADD COLUMN scan_id INTEGER")
        if statements:
            with engine.begin() as connection:
                for statement in statements:
                    connection.execute(text(statement))


def ensure_pgvector_index() -> None:
    if not artifacts_table_exists():
        return

    with engine.begin() as connection:
        connection.execute(
            text(
                "CREATE INDEX IF NOT EXISTS artifacts_embedding_vector_idx "
                "ON artifacts USING ivfflat (embedding_vector vector_cosine_ops) "
                "WITH (lists = 100)"
            )
        )


def artifacts_table_exists() -> bool:
    with engine.begin() as connection:
        return bool(
            connection.scalar(
                text("SELECT to_regclass('public.artifacts') IS NOT NULL")
            )
        )


def get_artifact_column_types() -> dict[str, str]:
    return get_table_column_types("artifacts")


def get_table_column_types(table_name: str) -> dict[str, str]:
    with engine.begin() as connection:
        if not connection.scalar(text(f"SELECT to_regclass('public.{table_name}') IS NOT NULL")):
            return {}

        rows = connection.execute(
            text(
                "SELECT a.attname AS column_name, "
                "format_type(a.atttypid, a.atttypmod) AS column_type "
                "FROM pg_attribute a "
                "JOIN pg_class c ON a.attrelid = c.oid "
                "JOIN pg_namespace n ON c.relnamespace = n.oid "
                "WHERE n.nspname = 'public' "
                "AND c.relname = :table_name "
                "AND a.attnum > 0 "
                "AND NOT a.attisdropped"
            ),
            {"table_name": table_name},
        ).all()

    return {
        row.column_name: str(row.column_type).lower()
        for row in rows
    }
