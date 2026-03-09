import os
from dotenv import load_dotenv
from google import genai

# Load .env
load_dotenv()

# Get API key from environment
api_key = os.getenv("GEMINI_API_KEY")

print("Loaded key:", api_key)  # debug (remove later)

client = genai.Client(api_key=api_key)

response = client.models.generate_content(
    model="gemini-3-flash-preview",
    contents="Explain SQL injection vulnerability in simple terms."
)

def triage_issue(issue):
    prompt = f"""
    You are a senior security triage engineer.

    Analyze the following vulnerability:

    Title: {issue['title']}
    Severity: {issue['severity']}
    File: {issue['file']}
    Message: {issue['message']}

    Return your response strictly in JSON format:

    {{
      "business_impact": "...",
      "exploit_likelihood": "...",
      "fix_priority": "Low | Medium | High | Critical",
      "recommended_action": "...",
      "reasoning": "..."
    }}
    """

    response = client.models.generate_content(
        model="gemini-1.5-pro",
        contents=prompt
    )

    return response.text

import json

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

for result in results:
    rule_id = result.get("ruleId")
    issue_data = rules.get(rule_id, {})

    title = issue_data.get("shortDescription", {}).get("text", "Unknown")
    severity = issue_data.get("defaultConfiguration", {}).get("level", "unknown")

    location = result["locations"][0]["physicalLocation"]
    file_path = location["artifactLocation"]["uri"]
    line = location["region"]["startLine"]

    message = result["message"]["text"]

    issue_entry = {
        "title": title,
        "rule_id": rule_id,
        "severity": severity,
        "file": file_path,
        "line": line,
        "message": message
    }

    issues.append(issue_entry)

for issue in issues:
    triage_result = triage_issue(issue)
    issue["triage"] = triage_result

print(issues[0])

