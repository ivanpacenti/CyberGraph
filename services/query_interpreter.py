import json
from services.campus_ai_api import get_text_response


def interpret_query(question: str) -> dict:
    prompt = f"""
            You are a cybersecurity query interpreter.
            
            Your task is to analyze the user question and return a JSON object.
            Return ONLY valid JSON, with no markdown and no explanation.
            
            Schema:
            {{
              "intent": "lookup_cve | mitigation_lookup | severity_search | software_search | unknown",
              "cve_id": string or null,
              "software": string or null,
              "severity": "CRITICAL | HIGH | MEDIUM | LOW" or null
            }}
            
            User question:
            {question}
            """

    raw = get_text_response(prompt)

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {
            "intent": "unknown",
            "cve_id": None,
            "software": None,
            "severity": None,
            "raw_output": raw,
        }