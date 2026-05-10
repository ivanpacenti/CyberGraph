import json
import re

from services.campus_ai_api import get_text_response


def clean_json_response(text: str) -> str:
    """
    Cleans the raw LLM output to ensure it is valid JSON.
    """
    text = text.strip()

    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)

    return text.strip()


def interpret_query(question: str) -> dict:
    """
    Uses an LLM to convert a natural language cybersecurity query
    into a structured JSON representation.
    """

    prompt = f"""
You are a cybersecurity query interpreter.

Return ONLY valid JSON.
Do not use markdown.
Do not explain anything.
Do not use code fences.

Allowed intents:
- lookup_cve
- mitigation_lookup
- severity_search
- software_search
- weakness_search
- vendor_search
- advanced_search
- unknown

JSON schema:
{{
  "intent": string,
  "cve_id": string or null,
  "software": string or null,
  "vendor": string or null,
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | null,
  "weakness": string or null,
  "wants_mitigation": boolean
}}

Examples:

Question:
"Which critical vulnerabilities affect Apache products?"

Output:
{{
  "intent": "advanced_search",
  "cve_id": null,
  "software": "Apache",
  "vendor": null,
  "severity": "CRITICAL",
  "weakness": null,
  "wants_mitigation": false
}}

Question:
"Find SQL injection vulnerabilities"

Output:
{{
  "intent": "weakness_search",
  "cve_id": null,
  "software": null,
  "vendor": null,
  "severity": null,
  "weakness": "SQL injection",
  "wants_mitigation": false
}}

User question:
{question}
"""

    raw = get_text_response(prompt, temperature=0.0)

    cleaned = clean_json_response(raw)

    print("RAW:", raw)
    print("CLEANED:", cleaned)

    try:
        parsed = json.loads(cleaned)

        return {
            "intent": parsed.get("intent", "unknown"),
            "cve_id": parsed.get("cve_id"),
            "software": parsed.get("software"),
            "vendor": parsed.get("vendor"),
            "severity": parsed.get("severity"),
            "weakness": parsed.get("weakness"),
            "wants_mitigation": parsed.get("wants_mitigation", False),
        }

    except json.JSONDecodeError:
        return {
            "intent": "unknown",
            "cve_id": None,
            "software": None,
            "vendor": None,
            "severity": None,
            "weakness": None,
            "wants_mitigation": False,
            "raw_output": raw,
        }