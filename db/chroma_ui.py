import streamlit as st
import chromadb
from chromadb.config import Settings
import os
import hashlib

# ----------------------------------
# Setup
# ----------------------------------

def show_issues_from_db():
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    persist_dir = os.path.join(BASE_DIR, "chroma_db")

    st.set_page_config(layout="wide")
    st.title("Snyk Issue Historical Search from DB")

    st.write("DB Path:", os.path.abspath(persist_dir))

    client = chromadb.Client(
        Settings(
            persist_directory=persist_dir,
            is_persistent=True
        )
    )

    collection = client.get_or_create_collection("vuln_results")

    # ----------------------------------
    # Session State Initialization
    # ----------------------------------

    if "search_results" not in st.session_state:
        st.session_state.search_results = None

    if "search_distances" not in st.session_state:
        st.session_state.search_distances = None

    if "search_mode" not in st.session_state:
        st.session_state.search_mode = "Semantic Search"

    # ----------------------------------
    # Browse Records
    # ----------------------------------

    st.title("Past AI Fixes Browser")
    st.caption("Search and explore previously generated AI fixes.")




    tab1, tab2 = st.tabs(["Browse Records", "Search Issues"])

    # =====================================================
    # SECTION 1 — Browse Records
    # =====================================================

    with tab1:
        st.subheader(" Browse Records")
        total_records = collection.count()
        col1, col2 = st.columns(2)
        col1.metric("Stored Vulnerabilities", total_records)
        col2.metric("Search Particular Issue from DB", total_records)

        page_size = 20
        page = st.number_input(
            "Page",
            min_value=1,
            max_value=max(1, (total_records // page_size) + 1),
            value=1
        )

        offset = (page - 1) * page_size

        if st.button("Load Page"):
            results = collection.get(limit=page_size, offset=offset)

            ids = results.get("ids", [])
            documents = results.get("documents", [])
            metadatas = results.get("metadatas", [])

            for i in range(len(ids)):
                st.markdown("---")
                st.markdown(f"### ID: `{ids[i]}`")

                colA, colB = st.columns(2)

                with colA:
                    st.markdown("#### Document")
                    st.code(documents[i])

                with colB:
                    st.markdown("#### Metadata")
                    st.json(metadatas[i])

        # ----------------------------------
        # Search Section
        # ----------------------------------

    st.divider()

    # =====================================================
    # 🔎 SECTION 2 — Search Memory
    # =====================================================

    with tab2:
        st.subheader("Search Particular Issue from DB")

        search_mode = st.radio(
            "Search Mode",
            ["Exact Code Match", "Semantic Search"],
            key="search_mode"
        )

        query_text = st.text_area("Enter Code Snippet or Query")

        # ----------------------------------
        # Filters
        # ----------------------------------

        col1, col2, col3 = st.columns(3)

        with col1:
            severity_filter = st.selectbox(
                "Severity",
                ["All", "Low", "Medium", "High", "Critical"]
            )

            rule_id_filter = st.text_input("Rule ID")

        with col2:
            filepath_filter = st.text_input("Filepath Contains")

        with col3:
            autofix_filter = st.selectbox(
                "Autofixable",
                ["All", "True", "False"]
            )

        conditions = []

        if severity_filter != "All":
            severity_map = {
                "Low": "note",
                "Medium": "warning",
                "High": "error",
                "Critical": "critical"
            }

            if severity_filter != "All":
                conditions.append({
                    "severity": severity_map.get(severity_filter, severity_filter)
                })

        if rule_id_filter:
            conditions.append({"rule_id": rule_id_filter})

        if filepath_filter:
            conditions.append({"filepath": {"$contains": filepath_filter}})

        if autofix_filter != "All":
            conditions.append({
                "is_autofixable": autofix_filter == "True"
            })

        where = {"$and": conditions} if conditions else None

        # ----------------------------------
        # Run Search
        # ----------------------------------

        if st.button("Run Search") and query_text.strip():

            # --------------------------
            # Exact Match Mode
            # --------------------------

            if search_mode == "Exact Code Match":

                normalized = "\n".join(
                    line.strip()
                    for line in query_text.strip().splitlines()
                    if line.strip()
                )

                code_hash = hashlib.sha256(normalized.encode()).hexdigest()

                results = collection.get(
                    where={"code_hash": code_hash},
                    include=["documents", "metadatas"]
                )

                ids = results.get("ids", [])
                documents = results.get("documents", [])
                metadatas = results.get("metadatas", [])

                st.session_state.search_results = {
                    "ids": ids,
                    "documents": documents,
                    "metadatas": metadatas
                }

                st.session_state.search_distances = None

            # --------------------------
            # Semantic Mode
            # --------------------------

            else:

                results = collection.query(
                    query_texts=[query_text],
                    n_results=20,
                    where=where if where else None
                )

                st.session_state.search_results = {
                    "ids": results.get("ids", [[]])[0],
                    "documents": results.get("documents", [[]])[0],
                    "metadatas": results.get("metadatas", [[]])[0]
                }

                st.session_state.search_distances = results.get("distances", [[]])[0]

        # ----------------------------------
        # Render Results (Persisted)
        # ----------------------------------

        if st.session_state.search_results:

            ids = st.session_state.search_results["ids"]
            documents = st.session_state.search_results["documents"]
            metadatas = st.session_state.search_results["metadatas"]
            distances = st.session_state.search_distances

            # Exact mode
            if st.session_state.search_mode == "Exact Code Match":

                if not ids:
                    st.warning("No exact match found.")
                else:
                    st.success(f"Found {len(ids)} exact match(es).")

                    for i in range(len(ids)):
                        st.markdown("---")
                        st.markdown(f"### ID: `{ids[i]}`")

                        colA, colB = st.columns(2)

                        with colA:
                            st.code(documents[i])

                        with colB:
                            st.json(metadatas[i])

            # Semantic mode
            else:

                similarity_threshold = st.slider(
                    "Minimum Similarity",
                    min_value=0.0,
                    max_value=1.0,
                    value=0.3,
                    step=0.05
                )

                filtered = []

                for i in range(len(ids)):
                    similarity = 1 - distances[i]
                    if similarity >= similarity_threshold:
                        filtered.append((i, similarity))

                if not filtered:
                    st.warning("No results above similarity threshold.")
                else:
                    st.success(f"{len(filtered)} result(s) above threshold")

                    for i, similarity in filtered:
                        st.markdown("---")
                        st.markdown(f"### ID: `{ids[i]}`")
                        st.markdown(f"Similarity: {similarity:.4f}")

                        colA, colB = st.columns(2)

                        with colA:
                            st.code(documents[i])

                        with colB:
                            st.json(metadatas[i])