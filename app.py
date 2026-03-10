import streamlit as st
import json
import os
from openai import OpenAI
from dotenv import load_dotenv
from rapidfuzz import fuzz
import difflib
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
    vuln_line = issue["line"]
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

with open("snyk-code-output.json") as f:
    data = json.load(f)

run = data["runs"][0]

rules = {}
for rule in run["tool"]["driver"]["rules"]:
    rules[rule["id"]] = rule

results = run.get("results", [])
issues = []

for result in results:
    rule_id = result.get("ruleId")
    issue_data = rules.get(rule_id, {})

    location = result["locations"][0]["physicalLocation"]

    snippet, snippet_start_line = extract_snippet_from_repo(
        location["artifactLocation"]["uri"],
        location["region"]["startLine"],
        location["region"]["endLine"]
    )

    issues.append({
        "title": issue_data.get("shortDescription", {}).get("text", "Unknown"),
        "severity": result.get("level", "unknown"),
        "message": result["message"]["text"],
        "file": location["artifactLocation"]["uri"],
        "line": location["region"]["startLine"],
        "code_snippet": snippet,
        "snippet_start_line": snippet_start_line
    })

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
        st.session_state.file_path = matched_issue["file"]
        st.session_state.line_number = matched_issue["line"]

        st.success(f"Matching issue found on Snyk with {score}% score and fields auto-filled.")

        highlighted = highlight_vulnerable_line(matched_issue)
        st.markdown("Vulnerable Code Lines Highlighted:")
        st.code(highlighted)
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

        prompt = f"""
You are a senior secure coding expert.

Vulnerability Title: {vuln_title}
Severity: {severity}

Vulnerable Code:
```{code_input}```

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
        st.code(result_json["fixed_code"])

        # Copy button
        copy_button_html = f"""
        <button onclick="navigator.clipboard.writeText(`{result_json['fixed_code']}`)">
        Copy Patch
        </button>
        """
        st.markdown(copy_button_html, unsafe_allow_html=True)
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