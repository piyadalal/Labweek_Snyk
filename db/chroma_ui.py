import streamlit as st
import chromadb
from chromadb.config import Settings
import os
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
persist_dir = os.path.join(BASE_DIR, "chroma_db")

st.set_page_config(layout="wide")
st.title("Snyk Issue Historical Search from DB")

# Connect to DB
client = chromadb.Client(
    Settings(
        persist_directory=persist_dir,
        is_persistent=True
    )
)

collections = client.list_collections()
if not collections:
    st.warning("No collections found in chroma_db")
    st.stop()

# ------------------------------
# Collection Summary
# ------------------------------
st.subheader("Collection Summary")
summary_data = {}
for c in collections:
    col = client.get_collection(c.name)
    summary_data[c.name] = col.count()
st.json(summary_data)

# ------------------------------
# Focus on vuln_results
# ------------------------------
if "vuln_results" not in summary_data:
    st.warning("vuln_results collection not found.")
    st.stop()

collection = client.get_collection("vuln_results")
st.subheader("Browse All Records")

total_records = collection.count()
st.write(f"Total Records: {total_records}")

page_size = 20
page = st.number_input("Page", min_value=1, max_value=max(1, (total_records // page_size) + 1), value=1)

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

st.subheader("Search & Filters")

# ------------------------------
# Semantic Search
# ------------------------------
query_text = st.text_input("Semantic Search (e.g. 'SQL injection in login')")

# ------------------------------
# Filters
# ------------------------------
col1, col2, col3 = st.columns(3)

with col1:
    severity_filter = st.selectbox(
        "Severity",
        ["All", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    )

    rule_id_filter = st.text_input("Rule ID (exact match)")

with col2:
    filepath_filter = st.text_input("Filepath contains")

    priority_min = st.number_input("Min Priority Score", value=0)
    priority_max = st.number_input("Max Priority Score", value=100)

with col3:
    autofix_filter = st.selectbox(
        "Autofixable",
        ["All", "True", "False"]
    )

    start_date = st.date_input("Start Date (optional)", value=None)
    end_date = st.date_input("End Date (optional)", value=None)

# ------------------------------
# Build WHERE filter (Chroma v2 compliant)
# ------------------------------
conditions = []

if severity_filter != "All":
    conditions.append({"severity": severity_filter})

if rule_id_filter:
    conditions.append({"rule_id": rule_id_filter})

if filepath_filter:
    conditions.append({"filepath": {"$contains": filepath_filter}})

# Only apply priority filter if user changed defaults
if priority_min != 0 or priority_max != 100:
    conditions.append({
        "priority_score": {
            "$gte": priority_min,
            "$lte": priority_max
        }
    })

if autofix_filter != "All":
    conditions.append({
        "is_autofixable": autofix_filter == "True"
    })

if start_date and end_date:
    conditions.append({
        "timestamp": {
            "$gte": start_date.isoformat(),
            "$lte": end_date.isoformat()
        }
    })

# Final where clause
where = {"$and": conditions} if conditions else None

# ------------------------------
# Execute Search
# ------------------------------
if st.button("Run Search"):

    if query_text:
        results = collection.query(
            query_texts=[query_text],
            n_results=20,
            where=where if where else None
        )
    else:
        results = collection.get(
            where=where if where else None,
            limit=20
        )

    # Normalize response structure
    if query_text:
        ids = results.get("ids", [[]])[0]
        documents = results.get("documents", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]
    else:
        ids = results.get("ids", [])
        documents = results.get("documents", [])
        metadatas = results.get("metadatas", [])
        distances = None

    TOLERANCE = 0.9999

    # Normalize distances safely
    valid_distances = distances if distances else []

    # Collect exact matches
    exact_matches = [
        i for i, d in enumerate(valid_distances)
        if (1 - d) >= TOLERANCE
    ]

    # Display results
    if not exact_matches:
        st.info("No exact matches found.")
    else:
        st.success(f"Found {len(exact_matches)} exact matches")

        for i in exact_matches:
            similarity = 1 - valid_distances[i]

            st.markdown("---")
            st.markdown(f"### ID: `{ids[i]}`")
            st.markdown(f"Similarity: {similarity:.4f}")

            colA, colB = st.columns(2)

            with colA:
                st.markdown("#### Document")
                st.code(documents[i] if i < len(documents) else "")

            with colB:
                st.markdown("#### Metadata")
                st.json(metadatas[i] if i < len(metadatas) else {})