import streamlit as st
import json
import os
from openai import OpenAI
from dotenv import load_dotenv
from rapidfuzz import fuzz
import subprocess
import hashlib
from Issue_embeddings import generate_fix_for_all_issues
from Code_Masking import code_mask, code_unmask
from db.vectordb import VulnerabilityVectorDB
from datetime import datetime, timezone
from Confluence_doc.fetch_db_issue_bulk import publish_vulnerability_report_to_confluence
from extract_snyk import export_snyk_rest_to_sarif
from Confluence_doc.fetch_db_issues import publish_vulnerability_report_to_confluence, fetch_issues_from_chroma
import urllib.parse


# ----------------------------------
# Init
# ----------------------------------

db = VulnerabilityVectorDB()
load_dotenv()

client = OpenAI(
    api_key=os.getenv("AZURE_OPENAI_API_KEY"),
    base_url=os.getenv("AZURE_ENDPOINT")
)
PROJECT_ROOT = "/Users/prda5207/PycharmProjects/Git_repos/Sky_E2E_Repo/sky-onbox-e2e-skyq-pa-automation"
GITHUB_REPO_URL = "https://github.com/1703/sky-onbox-e2e-skyq-pa-automation"
BRANCH = "main"

PROGRAMMING_LANGUAGES = ["Python", "JavaScript", "Java", "PHP"]
LESSONS_LINKS = {
    "Python": "https://learn.snyk.io/catalog/?format=lesson&categories=python",
    "JavaScript": "https://learn.snyk.io/catalog/?format=lesson&categories=javascript",
    "Java": "https://learn.snyk.io/catalog/?format=lesson&categories=java",
    "PHP": "https://learn.snyk.io/catalog/?format=lesson&categories=php"}



# ----------------------------------
# Utilities
# ----------------------------------

def map_serverity_to_ui(level):
    if not level:
        return "Low"
    level = level.lower()
    mapping = {
        "note": "Low",
        "warning": "Medium",
        "error": "High",
        "critical": "Critical"
    }
    return mapping.get(level, "Low")


def find_best_matching_issue(user_snippet, issues):
    best_match = None
    best_score = 0

    for issue in issues:
        snippet = issue.get("code_snippet")
        if snippet:
            score = fuzz.partial_ratio(user_snippet.strip(), snippet)
            if score > best_score:
                best_score = score
                best_match = issue

    return best_match, best_score

def extract_snippet_from_repo(file_path, start_line, end_line, context=3):
    full_path = os.path.join(PROJECT_ROOT, file_path)
    try:
        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        snippet_start = max(start_line - context - 1, 0)
        snippet_end = min(end_line + context, len(lines))

        snippet = "".join(lines[snippet_start:snippet_end])
        return snippet, snippet_start + 1
    except:
        return None, None


def find_best_matching_issue(user_snippet, issues):
    best_match = None
    best_score = 0

    for issue in issues:
        snippet = issue.get("code_snippet")
        if snippet:
            score = fuzz.partial_ratio(user_snippet.strip(), snippet)
            if score > best_score:
                best_score = score
                best_match = issue

    return best_match, best_score

def highlight_vulnerable_line(issue):
    snippet = issue["code_snippet"]
    vuln_line = issue["start_line"]
    snippet_start = issue["snippet_start_line"]

    lines = snippet.split("\n")
    formatted = []

    for i, line in enumerate(lines):
        actual_line = snippet_start + i
        if actual_line == vuln_line:
            formatted.append(f"{actual_line:>4} |  {line}")
        else:
            formatted.append(f"{actual_line:>4} | {line}")

    return "\n".join(formatted)

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
        severity= result.get("level", "unknown")
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

        snippet, snippet_start_line = extract_snippet_from_repo(
            filepath,
            start_line,
            end_line,
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
            "severity": severity,
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
            "code_snippet": snippet,
            "snippet_start_line": snippet_start_line
        }

        findings.append(finding)

    return findings
issues = extract_sarif_findings("snyk-code-output.json")

def show_feedback_page():
    st.title("Feedback & Support")

    st.markdown("Help us improve the AI-Powered Snyk Alert Triage tool.")

    feedback_type = st.selectbox(
        "Feedback Type",
        ["Bug Report", "Feature Request", "General Feedback"]
    )

    title = st.text_input("Title")

    description = st.text_area(
        "Describe the issue or suggestion",
        height=200
    )

    steps = ""
    if feedback_type == "Bug Report":
        steps = st.text_area(
            "Steps to reproduce",
            height=150
        )

    severity = st.selectbox(
        "Severity / Priority",
        ["Low", "Medium", "High", "Critical"]
    )

    name = st.text_input("Your Name (optional)")
    email = st.text_input("Your Email (optional)")

    screenshot = st.file_uploader(
        "Attach Screenshot (optional)",
        type=["png", "jpg", "jpeg"]
    )

    if st.button("Submit Feedback"):

        feedback_entry = {
            "type": feedback_type,
            "title": title,
            "description": description,
            "steps": steps,
            "severity": severity,
            "name": name,
            "email": email,
            "timestamp": datetime.utcnow().isoformat()
        }

        # -----------------------------
        # Save locally (optional)
        # -----------------------------
        feedback_file = "feedback_log.json"

        if os.path.exists(feedback_file):
            with open(feedback_file, "r") as f:
                existing = json.load(f)
        else:
            existing = []

        existing.append(feedback_entry)

        with open(feedback_file, "w") as f:
            json.dump(existing, f, indent=2)

        # -----------------------------
        # Build Outlook Mail Draft
        # -----------------------------

        recipient = "your.name@company.com"  # <-- change this

        subject = f"[AI Snyk Tool] {feedback_type} - {title}"

        body = f"""
Type: {feedback_type}
Severity: {severity}
Name: {name}
Email: {email}
Timestamp: {feedback_entry['timestamp']}

Description:
{description}

Steps:
{steps}
"""

        # URL encode safely
        encoded_subject = urllib.parse.quote(subject)
        encoded_body = urllib.parse.quote(body)

        mailto_link = f"mailto:{recipient}?subject={encoded_subject}&body={encoded_body}"

        st.success("Thank you! Click below to send the email via Outlook.")
        st.markdown(f"[📧 Open Outlook ]({mailto_link})")



# ----------------------------------
# Streamlit UI
# ----------------------------------

st.set_page_config(page_title="AI-Powered Snyk Alert Triage", layout="wide")
st.sidebar.markdown("Navigation")

if "page" not in st.session_state:
    st.session_state.page = "Issue Triage"

if st.sidebar.button("Issue Triage", use_container_width=True):
    st.session_state.page = "Issue Triage"

if st.sidebar.button("Feedback & Support", use_container_width=True):
    st.session_state.page = "Feedback & Support"

page = st.session_state.page
if page == "Issue Triage":

    st.title("AI-Powered Snyk Alert Triage")

    # ==================================================
    # Bulk Snyk Processing Section
    # ==================================================

    st.markdown("---")
    st.header(" Bulk Snyk Issue Processing")
    main_col1, main_col2, main_col3 = st.columns(3)


    # ----------------------------------
    # Generate Fix For All Issues
    # ----------------------------------
    with main_col1:

        if st.button("Extract Snyk Issues"):
            with st.spinner("Running scan on Snyk Portal..."):
                result, path , total_issues , count= export_snyk_rest_to_sarif()

            if result:
                data = result
                st.markdown("Snyk issue exported at:" + path)
                st.success(f"Issue export completed from Snyk")
            else:
                st.error("Scan failed")
                st.code(result.stderr)



    with main_col2:
        if st.button("Generate Fix for ALL Snyk Issues"):

            with st.spinner("Processing all Snyk issues..."):
                result = generate_fix_for_all_issues()

            st.success("Bulk processing completed!")

            # ----------------------------------
            # Summary Metrics
            # ----------------------------------

            col1, col2, col3, col4 = st.columns(4)

            col1.metric("Total Issues", result["total_issues"])
            col2.metric("Fixes Generated", result["generated"])
            col3.metric("Fixes Updated", result["updated"])
            col4.metric("Skipped (Already in DB)", result["skipped"])

            st.markdown("---")

            # ----------------------------------
            # Detailed Messages
            # ----------------------------------

            if result["skipped"] > 0:
                st.info(f"{result['skipped']} issue(s) already exist in DB. No LLM call made.")

            if result["generated"] + result["updated"] > 0:
                st.success(
                    f"LLM generated/updated fixes for "
                    f"{result['generated'] + result['updated']} issue(s)."
                )

            # Optional: Show detailed breakdown
            with st.expander("View Detailed Results"):
                for item in result["details"]:
                    if item["status"].startswith("Skipped"):
                        st.write(f" **{item['title']}** — Already exists in DB")
                    else:
                        st.write(f"**{item['title']}** — Fix generated by LLM")

            # for item in summary:
            #     st.write(f"**{item['title']}** — {item['status']}")

    # ----------------------------------
    # Generate Report
    # ----------------------------------

    with main_col3:
        if st.button("Generate Security Report"):
            status,url = publish_vulnerability_report_to_confluence()
            st.markdown("Published at : " + url)
            if status:
                st.info("Report generation completed.")
            else:
                st.error("Report generation failed.")

    # ----------------------------------
    # Session Defaults
    # ----------------------------------

    if "vuln_title" not in st.session_state:
        st.session_state.vuln_title = ""

    if "severity" not in st.session_state:
        st.session_state.severity = "Low"

    if "file_path" not in st.session_state:
        st.session_state.file_path = ""

    if "line_number" not in st.session_state:
        st.session_state.line_number = ""

    if "last_snippet" not in st.session_state:
        st.session_state.last_snippet = ""

    # ==================================================
    # SECTION 1: Single Issue Processing
    # ==================================================

    st.markdown("---")
    st.header(" Single Issue Processing")

    # ----------------------------------
    # Code Input
    # ----------------------------------

    code_input = st.text_area("Paste Vulnerable Code", height=300)

    # ----------------------------------
    # RESET + AUTOFILL (BEFORE WIDGETS)
    # ----------------------------------

    if code_input != st.session_state.last_snippet:
        st.session_state.last_snippet = code_input
        st.session_state.vuln_title = ""
        st.session_state.severity = "Low"
        st.session_state.file_path = ""
        st.session_state.line_number = ""

        if code_input.strip():
            matched_issue, score = find_best_matching_issue(code_input, issues)

            if matched_issue and score > 60:
                st.session_state.vuln_title = matched_issue["title"]
                st.session_state.severity = map_serverity_to_ui(matched_issue["severity"])
                st.session_state.file_path = matched_issue["filepath"]
                st.session_state.line_number = matched_issue["start_line"]

                st.success(f"Matching issue found on Snyk ({score:.2f}%)")

                highlighted = highlight_vulnerable_line(matched_issue)
                st.markdown("Vulnerable Code Lines Highlighted:")
                st.code(highlighted)

    # ----------------------------------
    # Editable Fields (ALWAYS VISIBLE)
    # ----------------------------------

    vuln_title = st.text_input("Vulnerability Title", key="vuln_title")
    severity = st.selectbox(
        "Severity",
        ["Low", "Medium", "High", "Critical"],
        key="severity"
    )

    if st.session_state.file_path:
        github_link = f"{GITHUB_REPO_URL}/blob/{BRANCH}/{st.session_state.file_path}#L{st.session_state.line_number}"
        st.markdown(f"[ Open in GitHub]({github_link})")

    # ----------------------------------
    # Generate Fix
    # ----------------------------------

    if st.button("Generate Fix") and code_input.strip():
        matched_issue, score = find_best_matching_issue(code_input, issues)
        # Mask for LLM
        # if matched_issue:
        #     language = matched_issue["ruleID"].split("/")[0]
        # else:
        #     language = "python"  # fallback



        if matched_issue and matched_issue.get("filepath"):
            ext = os.path.splitext(matched_issue["filepath"])[1]

            ext_map = {
                ".py": "python",
                ".js": "javascript",
                ".php": "php",
                ".java": "java"
            }

            language = ext_map.get(ext, "python")
        else:
            language = "python"

        masked_code, mapping = code_mask(code_input, language)

        st.session_state.mask_mapping = mapping
        st.session_state.mask_language = language

        st.subheader("Masked Code Sent to LLM")
        st.markdown(f"**Language:** `{language}`")
        st.code(masked_code, language=language)


        # -----------------------------
        # DB Lookup
        # -----------------------------



        db_record = None

        if matched_issue and score > 60:
            identity_string = f"{matched_issue.get('ruleID')}|{matched_issue.get('filepath')}|{matched_issue.get('start_line')}"
            doc_id = hashlib.sha256(identity_string.encode()).hexdigest()

            results = db.vuln_results.get(ids=[doc_id], include=["documents", "metadatas"])

            if results["ids"]:
                db_record = {
                    "id": results["ids"][0],
                    "document": results["documents"][0],
                    "metadata": results["metadatas"][0]
                }

        # -----------------------------
        # CASE 1: Use stored LLM
        # -----------------------------

        if db_record and db_record["metadata"].get("llm_stored_result"):
            stored = json.loads(db_record["metadata"]["llm_stored_result"])
            st.success("Using stored fix from DB.")
            result_json = stored

        else:
            # -----------------------------
            # CASE 2: Generate new LLM fix
            # -----------------------------

            with st.spinner("Generating secure fix..."):

                prompt = f"""
    Vulnerability Title: {vuln_title}
    Severity: {severity}
    
    Vulnerable Code:
    ```{masked_code}```
    
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

                result_json = json.loads(response.choices[0].message.content)

                # Update existing
                if db_record:
                    metadata = db_record["metadata"]
                    metadata["llm_stored_result"] = json.dumps(result_json)

                    db.vuln_results.upsert(
                        ids=[db_record["id"]],
                        documents=[db_record["document"]],
                        metadatas=[metadata]
                    )

                    st.success("LLM result updated in DB.")

                # Insert new
                else:
                    new_record = {
                        "ruleID": matched_issue.get("ruleID") if matched_issue else None,
                        "severity": severity,
                        "filepath": matched_issue.get("filepath") if matched_issue else None,
                        "start_line": matched_issue.get("start_line") if matched_issue else None,
                        "end_line": matched_issue.get("end_line") if matched_issue else None,
                        "priority_score": matched_issue.get("priority_score") if matched_issue else None,
                        "is_autofixable": matched_issue.get("is_autofixable") if matched_issue else None,
                        "code_snippet": code_input
                    }

                    db.store_vulnerability_result(new_record, result_json)
                    st.success("New record inserted in DB.")

        # ----------------------------------
        # Display Result
        # ----------------------------------

        col1, col2 = st.columns(2)

        with col1:
            st.subheader("Root Cause")
            st.write(result_json["root_cause"])
            st.subheader("Risk Assessment")
            st.write("Exploit Likelihood:", result_json["exploit_likelihood"])
            st.write("Fix Priority:", result_json["fix_priority"])
            st.write("Business Impact:", result_json["business_impact"])

        with col2:
            st.subheader("Secure Fix Explanation")
            st.write(result_json["secure_fix_explanation"])
            st.subheader("Fixed Code")

            restored_fix = code_unmask(
                result_json["fixed_code"],
                st.session_state.mask_mapping,
                st.session_state.mask_language
            )

            st.code(restored_fix)
    if st.button("Add issue to Report"):

        with st.spinner("Updating report..."):
            issues = fetch_issues_from_chroma()

        if not issues:
            st.error("No issues found in database.")
        else:
            with st.spinner("Publishing full report..."):
                status, url = publish_vulnerability_report_to_confluence(issues)
                st.markdown("Published at : " + url)
                if status:
                    st.success("Report generation completed.")
                else:
                    st.error("Report generation failed.")

elif page == "Feedback & Support":
    show_feedback_page()




