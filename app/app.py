import streamlit as st
from db.session import test_connection

st.set_page_config(page_title="Talend Knowledge Base", layout="wide")

st.title("Talend Knowledge Base")
st.write("Phase 1: Search-first MVP")

query = st.text_input("Search artifacts")
artifact_type = st.selectbox("Artifact Type", ["All", "Jobs", "Routines", "Joblets"])

col1, col2 = st.columns(2)

with col1:
    if st.button("Search"):
        if query.strip():
            st.info(f"Search will run for: '{query}' in '{artifact_type}'")
        else:
            st.warning("Enter a search term.")

with col2:
    if st.button("Test DB Connection"):
        try:
            test_connection()
            st.success("Database connection successful.")
        except Exception as e:
            st.error(f"Database connection failed: {e}")