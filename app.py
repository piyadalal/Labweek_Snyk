import streamlit as st
import json
import os
from openai import OpenAI
from dotenv import load_dotenv
from rapidfuzz import fuzz
import difflib
import streamlit.components.v1 as components
from Code_Masking import code_mask, code_unmask
from datetime import datetime, timezone
from db.vectordb import VulnerabilityDB

vuln_db = VulnerabilityDB()
# ------------------------
# Load Environment
# ------------------------

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

# ------------------------
# Utilities
# ------------------------
def map_serverity_to_ui(level):
    mapping = {
        "note": "Low",
        "warning": "Medium",
        "error": "High"
    }
    return mapping.get(level, "Low")

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
            formatted.append(f"{actual_line:>4} | ❌ {line}")
        else:
            formatted.append(f"{actual_line:>4} | {line}")

    return "\n".join(formatted)

# ------------------------
# Load Snyk Data
# ------------------------

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


# ------------------------
# Streamlit UI
# ------------------------

st.set_page_config(page_title="AI-Powered Snyk Alert Triage", layout="wide")
st.title("AI-Powered Snyk Alert Triage")

# ------------------------
# Session State Initialization
# ------------------------

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
if "code_input" not in st.session_state:
    st.session_state.code_input = ""

# ------------------------
# Code Input
# ------------------------

code_input = st.text_area("Paste Vulnerable Code", height=300)
# Detect language (basic example)
language = issues[0]["ruleID"].split("/")[0] # or detect dynamically from file extension

masked_code, mapping = code_mask(code_input, language)


st.subheader("Masked Code Sent to LLM")
st.code(masked_code)

# ------------------------
# Reset on Snippet Change
# ------------------------

if code_input != st.session_state.last_snippet:
    st.session_state.vuln_title = ""
    st.session_state.severity = "Low"
    st.session_state.file_path = ""
    st.session_state.line_number = ""
    st.session_state.last_snippet = code_input

# ------------------------
# Autofill Logic
# ------------------------

if code_input.strip():

    matched_issue, score = find_best_matching_issue(code_input, issues)

    if matched_issue and score > 60:

        st.session_state.vuln_title = matched_issue["title"]
        st.session_state.severity = map_serverity_to_ui(matched_issue["severity"])
        st.session_state.file_path = matched_issue["filepath"]
        st.session_state.line_number = matched_issue["start_line"]

        st.success(f"Matching issue found on Snyk with {score}% score.")

        highlighted = highlight_vulnerable_line(matched_issue)
        st.markdown("Vulnerable Code Lines Highlighted:")
        st.code(highlighted)

        # -------------------------------
        # 🔎 NEW: Check Vector DB FIRST
        # -------------------------------
        db_result = vuln_db.get_by_title_and_snippet(
            matched_issue["title"],
            matched_issue["code_snippet"]
        )

        if db_result:
            st.success("Found existing analysis in local DB. Skipping LLM.")

            stored_doc = db_result["documents"][0]

            st.subheader("Stored Analysis")
            st.code(stored_doc)

            st.stop()  # stop execution here → prevents LLM call

    else:
        st.error("No matching Snyk issue found.")
        st.warning("Please re-export your Snyk issues or verify repo path.")

    # ------------------------
    # Editable Fields (Always Visible)
    # ------------------------

    vuln_title = st.text_input("Vulnerability Title", key="vuln_title")
    severity = st.selectbox("Severity", ["Low", "Medium", "High", "Critical"], key="severity")

    if st.session_state.file_path:
        github_link = f"{GITHUB_REPO_URL}/blob/{BRANCH}/{st.session_state.file_path}#L{st.session_state.line_number}"
        st.markdown(f"[🔗 Open in GitHub]({github_link})")
    # ------------------------
    # Generate Fix
    # ------------------------

    if st.button("Generate Fix") and code_input.strip():

        with st.spinner("Generating secure fix..."):



            st.session_state["mask_mapping"] = mapping
            st.session_state["mask_language"] = language

            prompt = f"""
        You are a senior secure coding expert focused on analyzing vulnerabilities and providing secure code fixes.
        Use {PROGRAMMING_LANGUAGES} and {LESSONS_LINKS} to guide your analysis and recommendations.
        
    
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

            # Store LLM result
            if matched_issue:
                vuln_db.store(matched_issue, result_json)
                st.success("Stored analysis in the local DB.")

        st.success("Fix Generated")

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
            masked_fix = result_json["fixed_code"]

            mapping = st.session_state.get("mask_mapping", {})
            language = st.session_state.get("mask_language", "python")

            restored_fix = code_unmask(masked_fix, mapping, language)

            st.code(restored_fix)

            if st.button("📋 Copy Patch"):
                components.html(
                    f"""
                    <script>
                    navigator.clipboard.writeText(`{result_json['fixed_code']}`);
                    </script>
                    """,
                    height=0,
                )
                st.success("Patch copied to clipboard!")

            original = st.session_state.code_input.splitlines(keepends=True)
            fixed = result_json["fixed_code"].splitlines(keepends=True)

            diff = difflib.unified_diff(
                original,
                fixed,
                fromfile="original",
                tofile="fixed",
                lineterm=""
            )

            diff_text = "".join(diff)

            st.download_button(
                label="⬇ Download Patch (.diff)",
                data=diff_text,
                file_name="security_fix.patch",
                mime="text/plain"
            )