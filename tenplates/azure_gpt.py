from openai import OpenAI

endpoint = "https://rg-labweek-snyk-4610.openai.azure.com/openai/v1"
deployment_name = "gpt-4o-mini"
api_key = "9ZrXloEyj1RxD3FVQ9CBkgDZnUuOItmiyp0TrBoc5ucrTH6DSINDJQQJ99CCACmepeSXJ3w3AAABACOGp9Nt"

client = OpenAI(
    base_url=endpoint,
    api_key=api_key
)

completion = client.chat.completions.create(
    model=deployment_name,
    messages=[
        {
            "role": "user",
            "content": "What is the capital of France?",
        }
    ],
)

print(completion.choices[0].message)
