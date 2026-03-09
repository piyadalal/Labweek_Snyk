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


def get_code_snippet(file_path, line, context=5):
    try:
        with open(file_path, "r") as f:
            lines = f.readlines()

        start = max(line - context - 1, 0)
        end = min(line + context, len(lines))

        snippet = "".join(lines[start:end])
        return snippet

    except Exception as e:
        return f"Could not load file: {e}"

print(len(issues))
print(issues[-1])
for issue in issues:
    text = f"{issue['title']} : {issue['message']}"

print(text)