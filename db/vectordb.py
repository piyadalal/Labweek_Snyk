import os
import hashlib
from datetime import datetime, timezone
import chromadb
from chromadb.config import Settings
from chromadb.utils import embedding_functions
import re
import os
import json

BASE_DIR = os.path.dirname((os.path.abspath(__file__)))
persist_dir = os.path.join(BASE_DIR, "chroma_db")


class VulnerabilityVectorDB:
    def __init__(self, persist_directory: str = persist_dir):

        self.persist_directory = os.path.abspath(persist_directory)

        self.client = chromadb.Client(
            Settings(
                persist_directory=self.persist_directory,
                is_persistent=True
            )
        )

        self.embedding_function = embedding_functions.DefaultEmbeddingFunction()

        # Collection 1: Individual SARIF Results
        self.vuln_results = self.client.get_or_create_collection(
            name="vuln_results",
            embedding_function=self.embedding_function
        )

        # Collection 2: Rule Knowledge Base
        self.vuln_rules = self.client.get_or_create_collection(
            name="vulnerability_rules",
            embedding_function=self.embedding_function
        )

    # ---------------------------------------------------------
    # Utility: Deterministic ID generator
    # ---------------------------------------------------------
    def _generate_id(self, *args) -> str:
        raw = "|".join(str(a) for a in args)
        return hashlib.sha256(raw.encode()).hexdigest()

    def store_vulnerability_result(
            self,
            rule_id: str,
            severity: str,
            message: str,
            filepath: str,
            code_snippet: str,
            root_cause: str,
            fix_recommendation: str,
            start_line: int,
            end_line: int,
            priority_score: int,
            is_autofixable: bool
    ) -> str:
        doc_id = self._generate_id(rule_id, filepath, start_line, code_snippet)

        # EMBED ONLY CODE
        document_text = code_snippet.strip()

        # EVERYTHING ELSE → METADATA
        metadata = {
            "rule_id": rule_id,
            "severity": severity,
            "message": message,
            "root_cause": root_cause,
            "fix_recommendation": fix_recommendation,
            "filepath": filepath,
            "start_line": start_line,
            "end_line": end_line,
            "priority_score": priority_score,
            "is_autofixable": is_autofixable,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        self.vuln_results.upsert(
            ids=[doc_id],
            documents=[document_text],
            metadatas=[metadata]
        )

        return doc_id

    # ---------------------------------------------------------
    # Store Rule Definition
    # ---------------------------------------------------------
    def store_vulnerability_rule(
        self,
        rule_id: str,
        name: str,
        description: str,
        help_text: str,
        precision: str,
        cwe_list: list,
        tags: list,
        categories: list,
        repo_dataset_size: int
    ) -> str:

        doc_id = rule_id

        document_text = f"""
Rule ID: {rule_id}
Name: {name}

Description:
{description}

Help:
{help_text}

Precision: {precision}

CWE:
{", ".join(cwe_list)}
""".strip()

        metadata = {
            "rule_id": rule_id,
            "precision": precision.lower(),
            "cwe": cwe_list,
            "tags": tags,
            "categories": categories,
            "repo_dataset_size": repo_dataset_size
        }

        self.vuln_rules.add(
            ids=[doc_id],
            documents=[document_text],
            metadatas=[metadata]
        )

        return doc_id

    # ---------------------------------------------------------
    # Query Similar Vulnerability Results
    # ---------------------------------------------------------
    def query_similar_results(self, query_text: str, n_results: int = 5, filters: dict = None):
        return self.vuln_results.query(
            query_texts=[query_text],
            n_results=n_results,
            where=filters
        )

    # ---------------------------------------------------------
    # Query Rule Knowledge Base
    # ---------------------------------------------------------
    def query_rules(self, query_text: str, n_results: int = 3):
        return self.vuln_rules.query(
            query_texts=[query_text],
            n_results=n_results
        )

    # ---------------------------------------------------------
    # Summary
    # ---------------------------------------------------------
    def summary(self):
        return {
            "vuln_results_count": self.vuln_results.count(),
            "vulnerability_rules_count": self.vuln_rules.count()
        }