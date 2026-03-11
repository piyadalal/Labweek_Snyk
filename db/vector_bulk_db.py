import os
import hashlib
import json
from datetime import datetime, timezone
import chromadb
from chromadb.config import Settings
from chromadb.utils import embedding_functions

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
persist_dir = os.path.join(BASE_DIR, "chroma_db")


class VectorBulkDB:
    def __init__(self, persist_directory: str = persist_dir):

        self.persist_directory = os.path.abspath(persist_directory)

        self.client = chromadb.Client(
            Settings(
                persist_directory=self.persist_directory,
                is_persistent=True
            )
        )

        self.embedding_function = embedding_functions.DefaultEmbeddingFunction()

        self.vuln_results = self.client.get_or_create_collection(
            name="vuln_results",
            embedding_function=self.embedding_function
        )

    # ---------------------------------------------------------
    # Store SARIF Finding + LLM Result
    # ---------------------------------------------------------
    def store_vulnerability_result(self, issue: dict, result_json: dict | None):

        code_snippet = issue["code_snippet"].strip()

        identity_string = f"{issue.get('ruleID')}|{issue.get('filepath')}|{issue.get('start_line')}"
        doc_id = hashlib.sha256(identity_string.encode()).hexdigest()

        metadata = {
            "rule_id": issue.get("ruleID"),
            "severity": issue.get("level") or issue.get("severity"),
            "filepath": issue.get("filepath"),
            "start_line": issue.get("start_line"),
            "end_line": issue.get("end_line"),
            "priority_score": issue.get("priority_score"),
            "is_autofixable": issue.get("is_autofixable"),
            "timestamp": issue.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            "llm_stored_result": json.dumps(result_json) if result_json else None,
            "code_hash": doc_id
        }

        self.vuln_results.upsert(
            ids=[doc_id],
            documents=[code_snippet],
            metadatas=[metadata]
        )

        return doc_id

    def get_by_issue_identity(self, issue: dict):
        identity_string = f"{issue.get('ruleID')}|{issue.get('filepath')}|{issue.get('start_line')}"
        doc_id = hashlib.sha256(identity_string.encode()).hexdigest()

        results = self.vuln_results.get(
            ids=[doc_id],
            include=["documents", "metadatas"]
        )

        if results["ids"]:
            return {
                "id": results["ids"][0],
                "document": results["documents"][0],
                "metadata": results["metadatas"][0]
            }

        return None

    # ---------------------------------------------------------
    # Summary
    # ---------------------------------------------------------
    def summary(self):
        return {
            "vuln_results_count": self.vuln_results.count()
        }
    # ---------------------------------------------------------
    # Fetch All Stored Issues
    # ---------------------------------------------------------
    def fetch_all_issues(self):
        """
        Retrieve all stored vulnerability records from Chroma.
        """

        results = self.vuln_results.get(
            include=["documents", "metadatas"]
        )

        if not results or not results.get("ids"):
            return []

        issues = []

        for i in range(len(results["ids"])):
            issues.append({
                "id": results["ids"][i],
                "document": results["documents"][i],
                "metadata": results["metadatas"][i] or {}
            })

        return issues