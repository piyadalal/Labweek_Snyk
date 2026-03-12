import requests
import os
import json
from dotenv import load_dotenv
from urllib.parse import urljoin


def export_snyk_rest_to_sarif(output_file: str = "snyk-issues-sarif.json"):
    """
    Fetch all Snyk issues via REST API, convert to SARIF 2.1.0,
    save to file, and return (sarif_content, file_path, total_issues, sarif_results).
    """

    load_dotenv()

    org_id = "26c34c80-5bb6-433a-9deb-33c4f84a51e5"
    token = os.getenv("SNYK_TOKEN_LAB")

    if not token:
        raise ValueError("SNYK token is required")

    BASE_DOMAIN = "https://api.snyk.io"

    headers = {
        "Authorization": f"token {token}",
        "Content-Type": "application/vnd.api+json",
        "Accept": "application/vnd.api+json"
    }

    base_url = f"{BASE_DOMAIN}/rest/orgs/{org_id}/issues?version=2024-06-10&limit=100"

    # ----------------------------------
    #  Fetch ALL issues (pagination safe)
    # ----------------------------------

    all_issues = []
    next_url = base_url

    while next_url:
        full_url = urljoin(BASE_DOMAIN, next_url)

        response = requests.get(full_url, headers=headers)

        if not response.ok:
            raise Exception(f"Snyk API Error {response.status_code}: {response.text}")

        page = response.json()
        all_issues.extend(page.get("data", []))

        next_url = page.get("links", {}).get("next")

    total_issues = len(all_issues)
    print(f"Fetched {total_issues} total issues from Snyk REST API.")

    # ----------------------------------
    # onvert to SARIF
    # ----------------------------------

    rules_dict = {}
    results = []

    severity_map = {
        "low": "note",
        "medium": "warning",
        "high": "error",
        "critical": "error"
    }

    for issue in all_issues:
        attrs = issue.get("attributes", {})
        issue_id = issue.get("id")

        rule_id = attrs.get("key", issue_id)
        title = attrs.get("title", "Unknown Issue")
        description = attrs.get("description", "")
        severity = attrs.get("effective_severity_level", "low").lower()

        sarif_level = severity_map.get(severity, "warning")

        # Build rule only once
        if rule_id not in rules_dict:
            rules_dict[rule_id] = {
                "id": rule_id,
                "name": title,
                "shortDescription": {"text": description},
                "defaultConfiguration": {"level": sarif_level},
                "properties": {
                    "cwe": [c["id"] for c in attrs.get("classes", [])]
                }
            }

        coordinates = attrs.get("coordinates", [])
        if not coordinates:
            continue

        representations = coordinates[0].get("representations", [])
        if not representations:
            continue

        source = representations[0].get("sourceLocation", {})
        region = source.get("region", {})

        results.append({
            "ruleId": rule_id,
            "level": sarif_level,
            "message": {"text": title},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": source.get("file")},
                    "region": {
                        "startLine": region.get("start", {}).get("line"),
                        "endLine": region.get("end", {}).get("line")
                    }
                }
            }],
            "fingerprints": {"identity": issue_id}
        })

    sarif_results_count = len(results)
    print(f"Converted {sarif_results_count} issues into SARIF results.")
    print(f"Unique rules generated: {len(rules_dict)}")

    sarif_output = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Snyk REST Adapter",
                    "semanticVersion": "1.0.0",
                    "rules": list(rules_dict.values())
                }
            },
            "results": results
        }]
    }

    # ----------------------------------
    # ve file (overwrite)
    # ----------------------------------

    with open(output_file, "w") as f:
        json.dump(sarif_output, f, indent=2)

    absolute_path = os.path.abspath(output_file)

    print(f"SARIF file saved to: {absolute_path}")

    return sarif_output, absolute_path, total_issues, sarif_results_count


# ----------------------------------
# Run standalone
# ----------------------------------

if __name__ == "__main__":
    sarif, path, total, converted = export_snyk_rest_to_sarif("snyk-extracted-issues-new.json")

    print("\nSummary:")
    print(f"Total Issues Fetched: {total}")
    print(f"Total Issues Exported to SARIF: {converted}")