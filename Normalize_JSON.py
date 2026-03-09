import json

with open("snyk-code-output.json") as f:
    data = json.load(f)

run = data["runs"][0]

# Build rule lookup table
rules = {}
for rule in run["tool"]["driver"]["rules"]:
    rules[rule["id"]] = rule

results = run.get("results", [])

for issue in results:
    rule_id = issue.get("ruleId")
    rule = rules.get(rule_id, {})

    title = rule.get("shortDescription", {}).get("text", "Unknown")
    severity = rule.get("defaultConfiguration", {}).get("level", "unknown")

    location = issue["locations"][0]["physicalLocation"]
    file_path = location["artifactLocation"]["uri"]
    line = location["region"]["startLine"]

    message = issue["message"]["text"]

    print("Title:", title)
    print("Rule ID:", rule_id)
    print("Severity:", severity)
    print("File:", file_path)
    print("Line:", line)
    print("Message:", message)
    print("----")