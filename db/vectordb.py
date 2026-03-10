import chromadb
from chromadb.config import Settings
import hashlib
from datetime import datetime, timezone
import re
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
persist_dir = os.path.join(BASE_DIR, "chroma_db")

class VulnerabilityDB:

    def __init__(self, persist_dir = os.path.join(BASE_DIR, "chroma_db")):
        self.client = chromadb.Client(
            Settings(
                persist_directory=persist_dir,
                is_persistent=True
            )
        )
        print("Using Chroma DB at:", persist_dir)


        self.collection = self.client.get_or_create_collection(
            name="vulnerability_knowledge"
        )
        print("Collection count:", self.collection.count())

        # ---------------------------------------
        # Normalize Code
        # ---------------------------------------
    @staticmethod
    def normalize_code(code):
        if not code:
            return ""
        code = code.strip()
        code = code.replace("\r\n", "\n")
        code = re.sub(r"\n\s*\n", "\n", code)
        code = "\n".join(line.strip() for line in code.split("\n"))
        return code

    # ---------------------------------------
    # Create deterministic ID
    # ---------------------------------------
    def generate_id(self, rule_id, title, code_snippet):
        normalized_code = self.normalize_code(code_snippet)
        unique_string = f"{rule_id}:{title}:{normalized_code}"
        return hashlib.sha256(unique_string.encode()).hexdigest()
    # ---------------------------------------
    # Check if already exists
    # ---------------------------------------
    def get_existing(self, rule_id, title, code_snippet):

        doc_id = self.generate_id(rule_id, title, code_snippet)

        result = self.collection.get(ids=[doc_id])

        if result["documents"]:
            return result

        return None

    # ---------------------------------------
    # Store new vulnerability analysis
    # ---------------------------------------
    def store(self, issue, analysis_json):

        doc_id = self.generate_id(
            issue["ruleID"],
            issue["title"],
            issue["code_snippet"]
        )

        document_text = f"""
TITLE:
{issue['title']}

VULNERABILITY TYPE:
{issue['ruleID']}

VULNERABLE CODE:
{issue['code_snippet']}

ROOT CAUSE:
{analysis_json['root_cause']}

SECURE FIX EXPLANATION:
{analysis_json['secure_fix_explanation']}

FIXED CODE:
{analysis_json['fixed_code']}

BUSINESS IMPACT:
{analysis_json['business_impact']}
"""

        metadata = {
            "rule_id": issue["ruleID"],
            "title": issue["title"],
            "exploit_likelihood": analysis_json["exploit_likelihood"],
            "fix_priority": analysis_json["fix_priority"],
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        self.collection.add(
            ids=[doc_id],
            documents=[document_text],
            metadatas=[metadata]
        )

        self.client.persist()

        return doc_id