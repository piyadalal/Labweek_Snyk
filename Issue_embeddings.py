import json
from openai import OpenAI
import os
import datetime
from dotenv import load_dotenv
from datetime import datetime, timezone
from db.vectordb import VulnerabilityDB

vuln_db = VulnerabilityDB()
load_dotenv()


client = OpenAI(
    api_key=os.getenv("AZURE_OPENAI_API_KEY"),
    base_url=os.getenv("AZURE_ENDPOINT")
)


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
            "timestamp" : datetime.now(timezone.utc).isoformat(),
            "code_snippet": snippet
        }

        findings.append(finding)

    return findings

findings = extract_sarif_findings("snyk-code-output.json")
print(json.dumps(findings, indent=4))

for issue in findings:


    # print("\n==============================")
    # print("Vulnerability:", issue['title'])
    # print("File:", issue['filepath'])
    # print("Line:", issue['start_line'])
    # #print("Code:", issue['code_snippet'])
    print("\n--- Vulnerable Code ---\n")
    print(issue['code_snippet'])
    print("\n-----------------------\n")
    # ---------------------------------------
    # CHECK CACHE FIRST
    # ---------------------------------------
    existing = vuln_db.get_existing(
        issue["ruleID"],
        issue["title"],
        issue["code_snippet"]
    )

    if existing:
        print("Found in local DB. Skipping LLM.\n")

        stored_doc = existing["documents"][0]
        print("----- STORED RESULT -----\n")
        print(stored_doc)
        print("\n-------------------------\n")

        continue

    print("Not found in DB. Calling LLM...\n")

    prompt = f"""
    You are a senior secure coding expert.Analyze this vulnerability type and provide a secure fix.

    Vulnerability Title: {issue['title']}
        Message: {issue['message']}

        Vulnerable Code:
        ```{issue['code_snippet'] or 'Not provided'}```

    Return JSON:
    {{
      "root_cause": "",
      "secure_fix_explanation": "",
      "fixed_code": "",
      "business_impact": "",
      "exploit_likelihood": "Low|Medium|High",
      "fix_priority": "Low|Medium|High|Critical"
    }}
    """

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": "You are a senior secure coding expert."},
            {"role": "user", "content": prompt}
        ],
        temperature=0.2
    )

    result = response.choices[0].message.content

    analysis_json = json.loads(result)

    print("----- FIXED CODE -----\n")
    print(analysis_json["fixed_code"])
    print("\n----------------------\n")


    # {{
    #   "root_cause": "",
    #   "secure_fix_explanation": "",
    #   "fixed_code": "",
    #   "business_impact": "",
    #   "exploit_likelihood": "Low|Medium|High"
    # }}






