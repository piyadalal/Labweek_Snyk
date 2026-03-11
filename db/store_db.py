from vectordb import VulnerabilityVectorDB
import json
import os
import hashlib
from datetime import datetime, timezone


db = VulnerabilityVectorDB()
print("Using DB path:", db.persist_directory)
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


findings = extract_sarif_findings(
    "/Users/prda5207/Desktop/Snyk_Labweek_2026/Labweek_Snyk/snyk-code-output.json"
)

print("Total findings extracted:", len(findings))

inserted = 0

for issue in findings:
    try:
        db.store_vulnerability_result(
            rule_id=issue["ruleID"],
            severity=issue["level"],
            message=issue["message"],
            filepath=issue["filepath"],
            code_snippet=issue["code_snippet"],
            root_cause=issue["root_cause"],
            fix_recommendation=issue["secure_fix_explanation"],
            start_line=issue["start_line"],
            end_line=issue["end_line"],
            priority_score=issue.get("priority_score") or 0,
            is_autofixable=issue.get("is_autofixable") or False
        )
        inserted += 1

    except Exception as e:
        print(f"Error inserting issue {issue.get('ruleID')}: {e}")

print(f"Successfully inserted {inserted} findings into vuln_results")