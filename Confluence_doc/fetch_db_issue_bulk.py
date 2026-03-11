import os
import json
import html
import requests
from datetime import datetime
from dotenv import load_dotenv
import sys
import os

# Add project root to PYTHONPATH
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
load_dotenv()


def publish_vulnerability_report_to_confluence(bulk_db):
    """
    Publish vulnerability report directly from VectorBulkDB.
    """

    issues = bulk_db.fetch_all_issues()

    base_url = os.getenv("CONFLUENCE_BASE_URL")
    email = os.getenv("CONFLUENCE_EMAIL")
    api_token = os.getenv("CONFLUENCE_API_TOKEN")
    page_id = os.getenv("CONFLUENCE_PARENT_PAGE_ID")

    if not all([base_url, email, api_token, page_id]):
        raise ValueError("Missing Confluence environment variables.")

    # -------------------------------------------------------
    # 1️⃣ Get Current Page Version
    # -------------------------------------------------------
    get_url = f"{base_url}/rest/api/content/{page_id}?expand=version"
    response = requests.get(get_url, auth=(email, api_token))

    if response.status_code != 200:
        raise Exception(f"Failed to fetch page: {response.text}")

    page_data = response.json()
    current_version = page_data["version"]["number"]

    # -------------------------------------------------------
    # 2️⃣ Build Confluence Storage HTML
    # -------------------------------------------------------

    body = f"""
    <h1>Vulnerability Report</h1>
    <p><strong>Generated:</strong> {datetime.utcnow().isoformat()} UTC</p>
    <hr/>
    """

    if not issues:
        body += "<p><em>No vulnerabilities found.</em></p>"

    for issue in issues:

        meta = issue.get("metadata", {})
        code_snippet = issue.get("document", "")
        llm_raw = meta.get("llm_stored_result")

        root_cause = ""
        fixed_code = ""

        if llm_raw:
            try:
                llm_data = json.loads(llm_raw)
                root_cause = llm_data.get("root_cause", "")
                fixed_code = llm_data.get("fixed_code", "")
            except Exception:
                pass

        # Escape safely
        code_snippet = html.escape(code_snippet or "")
        fixed_code = html.escape(fixed_code or "")
        root_cause = html.escape(root_cause or "")

        body += f"""
        <h2>Issue: {issue.get("id","")}</h2>

        <ul>
            <li><strong>Rule:</strong> {meta.get("rule_id","")}</li>
            <li><strong>Severity:</strong> {meta.get("severity","")}</li>
            <li><strong>File:</strong> {meta.get("filepath","")}</li>
            <li><strong>Lines:</strong> {meta.get("start_line","")} - {meta.get("end_line","")}</li>
            <li><strong>Priority:</strong> {meta.get("priority_score","")}</li>
            <li><strong>Autofixable:</strong> {meta.get("is_autofixable","")}</li>
            <li><strong>Timestamp:</strong> {meta.get("timestamp","")}</li>
        </ul>
        """

        if root_cause:
            body += f"<h3>Root Cause</h3><p>{root_cause}</p>"

        if code_snippet:
            body += f"""
            <h3>Original Code</h3>
            <ac:structured-macro ac:name="code">
                <ac:parameter ac:name="language">python</ac:parameter>
                <ac:plain-text-body><![CDATA[{code_snippet}]]></ac:plain-text-body>
            </ac:structured-macro>
            """

        if fixed_code:
            body += f"""
            <h3>Fixed Code</h3>
            <ac:structured-macro ac:name="code">
                <ac:parameter ac:name="language">python</ac:parameter>
                <ac:plain-text-body><![CDATA[{fixed_code}]]></ac:plain-text-body>
            </ac:structured-macro>
            """
        else:
            body += "<p><em>No fixed code generated.</em></p>"

        body += "<hr/>"

    # -------------------------------------------------------
    # 3️⃣ Update Page
    # -------------------------------------------------------

    update_url = f"{base_url}/rest/api/content/{page_id}"

    payload = {
        "id": page_id,
        "type": "page",
        "title": page_data["title"],
        "version": {"number": current_version + 1},
        "body": {
            "storage": {
                "value": body,
                "representation": "storage"
            }
        }
    }

    update_response = requests.put(
        update_url,
        json=payload,
        auth=(email, api_token),
        headers={"Content-Type": "application/json"}
    )

    if update_response.status_code != 200:
        raise Exception(f"Update failed: {update_response.text}")

    print(" Confluence page updated successfully.")


if __name__ == "__main__":
    from db.vector_bulk_db import VectorBulkDB

    bulk_db = VectorBulkDB()
    publish_vulnerability_report_to_confluence(bulk_db)