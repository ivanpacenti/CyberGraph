from services.campus_ai_api import get_text_response


def explain_vulnerability(cve: dict) -> str:
    prompt = f"""
You are a cybersecurity assistant.

Write a short explanation in plain English using ONLY the provided data.
Do not invent facts.
Do not change the severity level.
If mitigation is not explicitly available, say that no explicit mitigation is provided in the structured data.

Structured vulnerability data:
- CVE ID: {cve.get("id")}
- Description: {cve.get("description")}
- Severity: {cve.get("severity")}
- Score: {cve.get("score")}
- Products: {cve.get("product_names")}
- References: {cve.get("references")[:5]}

Write:
1. What the vulnerability is
2. Which product is affected
3. Severity and score
4. Whether a mitigation is explicitly available from the data
"""
    return get_text_response(prompt, temperature=0.0)