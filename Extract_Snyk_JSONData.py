import requests

SNYK_TOKEN = "YOUR_SNYK_API_TOKEN"
ORG_ID = "YOUR_ORG_ID"

url = f"https://api.snyk.io/rest/orgs/{ORG_ID}/projects"

headers = {
    "Authorization": f"token {SNYK_TOKEN}",
    "Content-Type": "application/vnd.api+json",
    "Accept": "application/vnd.api+json"
}

params = {
    "version": "2024-01-01"  # required for REST API
}

response = requests.get(url, headers=headers, params=params)

if response.status_code == 200:
    data = response.json()
    print(data)  # JSON output
else:
    print("Error:", response.status_code, response.text)