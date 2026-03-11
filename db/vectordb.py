import chromadb
from chromadb.config import Settings
import hashlib
from datetime import datetime, timezone
import re
import os
import json

BASE_DIR = os.path.dirname((os.path.abspath(__file__)))
persist_dir = os.path.join(BASE_DIR, "chroma_db")

class VulnerabilityDB:

    def __init__(self, persist_dir = os.path.join(BASE_DIR, "chroma_db")):
        self.client = chromadb.PersistentClient(path=persist_dir)
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

    def get_by_filter(self, filters: dict):
        """
        Retrieve documents using metadata filtering.

        Example:
            get_by_filter({"title": "Cross-site scripting"})
            get_by_filter({"rule_id": "php/XSS", "severity": "High"})
        """

        results = self.collection.get(where=filters)

        if results and results["documents"]:
            return results

        return None

    def get_by_title(self, title):
        results = self.collection.get(
            where={"title": title}
        )

        if results["documents"]:
            return results

        return None

    def get_all(self):
        """
        Fetch all records from the collection and pretty print them.
        """

        total_count = self.collection.count()

        if total_count == 0:
            print("No records found in the database.")
            return

        results = self.collection.get(limit=total_count)

        print(f"\n========== Total Records: {total_count} ==========\n")

        for i in range(total_count):
            doc_id = results["ids"][i]
            metadata = results["metadatas"][i]
            document = results["documents"][i]

            print("--------------------------------------------------")
            print(f"ID: {doc_id}")
            print(f"Title: {metadata.get('title', 'N/A')}")
            print(f"Rule ID: {metadata.get('rule_id', 'N/A')}")
            print(f"Severity: {metadata.get('severity', 'N/A')}")
            print(f"File: {metadata.get('filepath', 'N/A')}")
            print(f"Line: {metadata.get('start_line', 'N/A')}")
            print(f"Priority Score: {metadata.get('priority_score', 'N/A')}")
            print(f"Autofixable: {metadata.get('is_autofixable', 'N/A')}")
            print(f"Timestamp: {metadata.get('timestamp', 'N/A')}")

            print("\n--- Document Preview ---")
            print(document[:500])
            print("\n--------------------------------------------------\n")

    def get_by_title_and_snippet(self, title, code_snippet):
        normalized_snippet = self.normalize_code(code_snippet)

        results = self.collection.get(
            where={
                "title": title,
                "code_snippet": normalized_snippet
            }
        )

        if results and results.get("documents"):
            return results

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

    RULE ID:
    {issue['ruleID']}

    SEVERITY:
    {issue['level']}

    FILE:
    {issue['filepath']}

    VULNERABLE CODE:
    {issue['code_snippet']}

    ROOT CAUSE:
    {analysis_json.get('root_cause', '')}

    SECURE FIX EXPLANATION:
    {analysis_json.get('secure_fix_explanation', '')}

    FIXED CODE:
    {analysis_json.get('fixed_code', '')}

    BUSINESS IMPACT:
    {analysis_json.get('business_impact', '')}

    EXPLOIT LIKELIHOOD:
    {analysis_json.get('exploit_likelihood', '')}

    FIX PRIORITY:
    {analysis_json.get('fix_priority', '')}
    """

        metadata = {
            "rule_id": issue["ruleID"],
            "title": issue["title"],
            "severity": issue["level"],
            "filepath": issue["filepath"],
            "start_line": issue["start_line"],
            "code_snippet": self.normalize_code(issue["code_snippet"]),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        self.collection.add(
            ids=[doc_id],
            documents=[document_text],
            metadatas=[metadata]
        )

        return doc_id






def main():
    db = VulnerabilityDB()

    PROJECT_ROOT = "/Users/prda5207/PycharmProjects/Git_repos/Sky_E2E_Repo/sky-onbox-e2e-skyq-pa-automation"

    def extract_snippet_from_repo(file_path, start_line, end_line, context=3):
        full_path = os.path.join(PROJECT_ROOT, file_path)

        try:
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            # Add surrounding context
            start = max(start_line - context - 1, 0)
            end = min(end_line + context, len(lines))

            snippet = "".join(lines[start:end])
            return snippet

        except Exception as e:
            return f"Error reading file: {e}"

    def extract_sarif_findings(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            sarif = json.load(f)

        run = sarif["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        results = run.get("results", [])
        # Build rule lookup map
        rule_map = {rule["id"]: rule for rule in rules}

        findings = []

        for result in results:
            rule_id = result.get("ruleId")
            rule = rule_map.get(rule_id, {})

            # -----------------------------
            # Rule-level data
            # -----------------------------
            title = rule.get("name")
            short_description = rule.get("shortDescription", {}).get("text", "")
            help_markdown = rule.get("help", {}).get("markdown", "")
            cwe = rule.get("properties", {}).get("cwe", [])

            # Extract CWE if exists
            cwe_list = ", ".join(cwe) if isinstance(cwe, list) else ""

            # -----------------------------
            # Result-level data
            # -----------------------------
            message = result.get("message", {}).get("text", "")
            level = result.get("level")

            # Location info
            location = result.get("locations", [{}])[0]
            physical = location.get("physicalLocation", {})
            artifact = physical.get("artifactLocation", {})
            region = physical.get("region", {})

            filepath = artifact.get("uri")
            uri = artifact.get("uriBaseId")

            start_line = region.get("startLine")
            end_line = region.get("endLine")
            snippet = extract_snippet_from_repo(
                filepath,
                start_line,
                end_line
            )
            fingerprint = result.get("fingerprints", {}).get("identity")

            # Properties
            properties = result.get("properties", {})
            priority_score = properties.get("priorityScore")
            is_autofixable = properties.get("isAutofixable")

            # -----------------------------
            # Extract example fix (if exists)
            # -----------------------------
            example_fixes = rule.get("properties", {}).get("exampleCommitFixes", [])

            fixed_code_lines = []
            github_link = None

            if example_fixes:
                github_link = example_fixes[0].get("commitURL")

                for line in example_fixes[0].get("lines", []):
                    if line.get("lineChange") == "added":
                        fixed_code_lines.append(line.get("line"))

            fixed_code = "\n".join(fixed_code_lines)

            # -----------------------------
            # Build structured object
            # -----------------------------
            finding = {
                "id": fingerprint,
                "ruleID": rule_id,
                "title": title,
                "short_description": short_description,
                "message": message,
                "level": level,
                "cwe": cwe_list,
                "filepath": filepath,
                "uri": uri,
                "start_line": start_line,
                "end_line": end_line,
                "root_cause": short_description,
                "secure_fix_explanation": help_markdown,
                "fixed_code": fixed_code,
                "business_impact": help_markdown,
                "priority_score": priority_score,
                "is_autofixable": is_autofixable,
                "github_link": github_link,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "code_snippet": snippet
            }

            findings.append(finding)

        return findings

    findings = extract_sarif_findings("/Users/prda5207/Desktop/Snyk_Labweek_2026/Labweek_Snyk/snyk-code-output.json")
    print("Total findings extracted:", len(findings))
    for issue in findings:
        db.store(issue, analysis_json={"secute_fix_explanation": "This is a placeholder explanation for the secure fix.", "business_impact": "This is a placeholder explanation for the business impact.", "exploit_likelihood": "Medium", "fix_priority": "High"})
    unique_ids = set()

    for issue in findings:
        doc_id = db.generate_id(
            issue["ruleID"],
            issue["title"],
            issue["code_snippet"]
        )
        unique_ids.add(doc_id)

    print("Unique generated IDs:", len(unique_ids))
    print("After insert count:", db.collection.count())
    print("Current DB count:", db.collection.count())
    result = db.get_all()

    if result:
        print(result)
def main__():
    pass

if __name__ == "__main__":
    main()

