import boto3


session = boto3.Session()
credentials = session.get_credentials()

print("Access Key:", credentials.access_key if credentials else "None")
print("Region:", session.region_name)

import json

client = boto3.client("bedrock-runtime", region_name="us-east-1")

prompt = """
You are a security triage assistant.
Explain SQL injection risk.
"""

response = client.invoke_model(
    modelId="anthropic.claude-3-sonnet-20240229-v1:0",
    body=json.dumps({
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 500
    })
)

result = json.loads(response["body"].read())
print(result)