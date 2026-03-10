import chromadb
from chromadb.config import Settings
from datetime import datetime
from uuid import uuid4

# -----------------------------
# 1. Initialize persistent DB
# -----------------------------
client = chromadb.Client(
    Settings(
        persist_directory="./chroma_db",  # folder where data is stored
        is_persistent=True
    )
)

# Create or load collection
collection = client.get_or_create_collection(
    name="security_vulnerabilities"
)

# -----------------------------
# 2. Prepare Data
# -----------------------------
entry_id = str(uuid4())

vulnerability_type = "Cross-site Scripting (XSS)"
vulnerable_code = """<input id='rowid' type='hidden' name='rowid' value='$rowid'>
    $htmlStrExtra
<hr>
EOT;
print $htmlStr;"""
root_cause = "The code directly outputs user-controlled data (rowid and htmlStrExtra) into the HTML without proper sanitization or escaping, making it vulnerable to Cross-site Scripting (XSS) attacks. An attacker could inject malicious scripts that would execute in the context of the user's browser."
secure_fix = "To mitigate the XSS vulnerability, user input should be properly sanitized and escaped before being output to the HTML. This can be achieved by using functions that encode special characters in HTML, such as htmlspecialchars() in PHP."
fixed_code = """<input id='rowid' type='hidden' name='rowid' value='<?php echo htmlspecialchars($rowid, ENT_QUOTES, 'UTF-8'); ?>'>
            <?php echo htmlspecialchars($htmlStrExtra, ENT_QUOTES, 'UTF-8'); ?>
        <hr>"""
business_impact = "If exploited, XSS vulnerabilities can lead to session hijacking, defacement of web pages, phishing attacks, and unauthorized actions on behalf of users, potentially resulting in loss of customer trust, financial loss, and legal repercussions."
exploit_likelihood = "High"
language = "PHP"

# Document = everything that should be semantically searchable
document_text = f"""
VULNERABILITY TYPE:
{vulnerability_type}

VULNERABLE CODE:
{vulnerable_code}

ROOT CAUSE:
{root_cause}

SECURE FIX EXPLANATION:
{secure_fix}

FIXED CODE:
{fixed_code}

BUSINESS IMPACT:
{business_impact}

"""

# Metadata = structured/filterable data
metadata = {
    "timestamp": datetime.utcnow().isoformat(),
    "filepath": "src/auth/login.py",
    "github_link": "https://github.com/org/repo/login.py",
    "exploit_likelihood": "High"
}

# -----------------------------
# 3. Add to Chroma
# -----------------------------
collection.add(
    ids=[entry_id],
    documents=[document_text],
    metadatas=[metadata]
)

# Persist to disk
client.persist()

print("Entry stored successfully.")