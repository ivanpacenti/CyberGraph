import json
import re

from services.campus_ai_api import get_text_response


def clean_json_response(text: str) -> str:
    text = text.strip()

    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)

    return text.strip()


def interpret_query(question: str) -> dict:
    prompt = f"""
You are a cybersecurity query interpreter.

Return ONLY valid JSON.
Do not use markdown.
Do not use code fences.

Schema:
{{
  "intent": "lookup_cve | mitigation_lookup | severity_search | software_search | software_severity_search | unknown",
  "cve_id": string or null,
  "software": string or null,
  "severity": "CRITICAL | HIGH | MEDIUM | LOW" or null,
  "wants_mitigation": boolean
}}

User question:
{question}
"""

    raw = get_text_response(prompt, temperature=0.0)
    cleaned = clean_json_response(raw)
    print("RAW:", raw)
    print("CLEANED:", cleaned)

    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return {
            "intent": "unknown",
            "cve_id": None,
            "software": None,
            "severity": None,
            "wants_mitigation": False,
            "raw_output": raw,
        }