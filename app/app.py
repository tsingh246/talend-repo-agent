import streamlit as st

from db.init_db import init_db
from db.session import SessionLocal, test_connection
from repositories.artifact_repository import create_sample_artifacts, get_all_artifacts
from services.scan_service import scan_repositories
from services.artifact_summarization_service import summarize_all_artifacts
from repositories.artifact_repository import (
    create_sample_artifacts,
    get_all_artifacts,
    insert_artifacts,
)
st.set_page_config(page_title="Talend Knowledge Base", layout="wide")

st.title("Talend Knowledge Base")
st.write("Phase 1: Search-first MVP")


def extract_sql_search_signature(search_text: str | None) -> str:
    if not search_text:
        return ""
    for token in str(search_text).split():
        if token.startswith("sql_preview_"):
            return token.replace("sql_preview_", "").replace("_", " ")
    return ""

query = st.text_input("Search artifacts")
artifact_type = st.selectbox("Artifact Type", ["All", "Jobs", "Routines", "Joblets"])

col1, col2, col3, col4 = st.columns(4)

with col1:
    if st.button("Test DB Connection"):
        try:
            test_connection()
            st.success("Database connection successful.")
        except Exception as e:
            st.error(f"Database connection failed: {e}")

with col2:
    if st.button("Initialize Database"):
        try:
            init_db()
            st.success("Database tables created successfully.")
        except Exception as e:
            st.error(f"Database initialization failed: {e}")

with col3:
    if st.button("Load Sample Data"):
        try:
            init_db()
            with SessionLocal() as db:
                create_sample_artifacts(db)
            st.success("Sample artifacts loaded.")
        except Exception as e:
            st.error(f"Loading sample data failed: {e}")

with col4:
    if st.button("Generate Summaries"):
        try:
            processed, failed = summarize_all_artifacts()
            st.success(f"Summaries generated. Processed: {processed}, Failed: {failed}")
        except Exception as e:
            st.error(f"Summary generation failed: {e}")
st.divider()

if st.button("Show All Artifacts"):
    try:
        with SessionLocal() as db:
            artifacts = get_all_artifacts(db)

        if not artifacts:
            st.info("No artifacts found.")
        else:
            for artifact in artifacts:
                with st.container():
                    st.subheader(artifact.name)
                    st.write(f"**Type:** {artifact.artifact_type}")
                    st.write(f"**Project:** {artifact.project_name}")
                    st.write(f"**Repo:** {artifact.repo_name}")
                    st.write(f"**File Path:** {artifact.file_path}")
                    st.write(f"**Components:** {artifact.component_types}")
                    st.write(f"**Summary:** {artifact.summary}")
                    sql_signature = extract_sql_search_signature(artifact.search_text)
                    if sql_signature:
                        st.write(f"**SQL Search Signature:** {sql_signature}")
                    st.write(f"**Search Text:** {artifact.search_text[:500]}")
                    st.write(f"**Embedding Text:** {artifact.embedding_text[:500] if artifact.embedding_text else ''}")
                    st.divider()
    except Exception as e:
        st.error(f"Failed to fetch artifacts: {e}")

if st.button("Scan Local Repositories"):
    try:
        init_db()

        artifacts = scan_repositories()

        if not artifacts:
            st.warning("No artifacts found in data/repos/")
        else:
            with SessionLocal() as db:
                insert_artifacts(db, artifacts)

            st.success(f"Discovered and stored {len(artifacts)} artifacts.")

    except Exception as e:
        st.error(f"Scan failed: {e}")