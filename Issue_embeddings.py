import json
from openai import OpenAI
import os

from dotenv import load_dotenv
load_dotenv()

client = OpenAI(
    api_key=os.getenv("AZURE_OPENAI_API_KEY"),
    base_url=os.getenv("AZURE_ENDPOINT")
)


PROJECT_ROOT = "/Users/prda5207/PycharmProjects/Git_repos/Sky_E2E_Repo/sky-onbox-e2e-skyq-pa-automation"


with open("snyk-code-output.json") as f:
    data = json.load(f)

run = data["runs"][0]

# Build rule lookup table
rules = {}
for rule in run["tool"]["driver"]["rules"]:
    rules[rule["id"]] = rule

results = run.get("results", [])

# Store extracted issues here
issues = []

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

for result in results:
    rule_id = result.get("ruleId")
    issue_data = rules.get(rule_id, {})

    title = issue_data.get("shortDescription", {}).get("text", "Unknown")
    severity = issue_data.get("defaultConfiguration", {}).get("level", "unknown")

    location = result["locations"][0]["physicalLocation"]
    file_path = location["artifactLocation"]["uri"]
    line = location["region"]["startLine"]

    message = result["message"]["text"]
    snippet = extract_snippet_from_repo(
        file_path,
        location["region"]["startLine"],
        location["region"]["endLine"]
    )
    #snippet = extract_snippet(result)

    issue_entry = {
        "title": title,
        "rule_id": rule_id,
        "severity": severity,
        "file": file_path,
        "line": line,
        "message": message,
        "code_snippet": snippet
    }


    issues.append(issue_entry)

for issue in issues:
    text = f"""
    Vulnerability Title: {issue['title']}
    Severity: {issue['severity']}
    Message: {issue['message']}

    Vulnerable Code:
    ```{issue.get('code_snippet', 'Not provided')}```
    """
    snippet = issue.get('code_snippet') or 'Not provided'

    print("\n==============================")
    print("Vulnerability:", issue['title'])
    print("Severity:", issue['severity'])
    print("File:", issue['file'])
    print("Line:", issue['line'])
    print("\n--- Vulnerable Code ---\n")
    print(snippet)
    print("\n-----------------------\n")

    response = client.chat.completions.create(
        model="gpt-4o-mini",
        response_format={"type": "json_object"},
        messages=[
            {
                "role": "system",
                "content": "You are a senior secure coding expert."
            },
            {
                "role": "user",
                "content": f"""
    Analyze this vulnerability and provide a secure fix.

    Title: {issue['title']}
    Severity: {issue['severity']}
    Message: {issue['message']}

    Vulnerable Code:
    ```{issue.get('code_snippet') or 'Not provided'}```

    Return JSON:
    {{
      "fixed_code": ""
    }}
    """
            }
        ],
        temperature=0.2
    )

    result = response.choices[0].message.content

    result = response.choices[0].message.content
    analysis_json = json.loads(result)

    print("Fix Generated.\n")

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






