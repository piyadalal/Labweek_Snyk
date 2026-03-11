import streamlit as st
import chromadb
from chromadb.config import Settings
import re
import os
import json

BASE_DIR = os.path.dirname((os.path.abspath(__file__)))
persist_dir = os.path.join(BASE_DIR, "chroma_db")

st.title("Vector DB Viewer")

# Connect directly to local persistent DB folder
client = chromadb.Client(
    Settings(
        persist_directory = persist_dir , # <-- IMPORTANT
        is_persistent=True
    )
)

collections = client.list_collections()

if not collections:
    st.warning("No collections found in chroma_db")
else:
    collection_names = [c.name for c in collections]
    selected = st.selectbox("Select Collection", collection_names)

    collection = client.get_collection(selected)

    st.write("### Collection Info")
    st.write("Document count:", collection.count())

    if st.button("Load Sample Documents"):
        results = collection.get(limit=10)
        st.write(results)