import json
import re

from services.campus_ai_api import get_text_response


def clean_json_response(text: str) -> str:
    """
    Cleans the raw LLM output to ensure it is valid JSON.

    Large Language Models sometimes return responses wrapped in markdown
    code blocks (e.g. ```json ... ```), which are not valid JSON strings
    and would break json.loads().

    This function:
    - Strips whitespace
    - Removes markdown code fences if present
    - Returns a clean JSON string
    """
    text = text.strip()

    # Remove markdown code block markers like ```json ... ```
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)  # remove opening ```
        text = re.sub(r"\s*```$", "", text)  # remove closing ```

    return text.strip()


def interpret_query(question: str) -> dict:
    """
    Uses an LLM (CampusAI) to interpret a natural language query
    into a structured JSON representation.
    The LLM is instructed to extract:
    - intent (type of query)
    - cve_id (if present)
    - software name (if present)
    - severity level (if present)
    - whether mitigation is requested
    This structured output is then used by the backend service layer
    to decide which retrieval logic to apply (lookup, filtering, etc.).
    """

    # model has to return only json
    # with a fixed schema to make parsing deterministic.
    prompt = f"""
    You are a cybersecurity query interpreter.

    Return ONLY valid JSON.
    Do not use markdown.
    Do not use code fences.

    Schema:
    {{
      "intent": "lookup_cve | mitigation_lookup | severity_search | software_search | software_severity_search | advanced_search | unknown",
      "cve_id": string or null,
      "software": string or null,
      "severity": "CRITICAL | HIGH | MEDIUM | LOW" or null,
      "weakness": string or null,
      "wants_mitigation": boolean
    }}

    User question:
    {question}
    """
    # Send request to LLM
    raw = get_text_response(prompt, temperature=0.0)

    # Clean possible markdown formatting from LLM output
    cleaned = clean_json_response(raw)

    # only for debug
    print("RAW:", raw)
    print("CLEANED:", cleaned)

    try:
        # Try to parse the cleaned string into a Python dictionary
        return json.loads(cleaned)

    except json.JSONDecodeError:
        """
        If parsing fails, a safe fallback response is returned.
        This ensures the system does not crash and can still respond,
        even if the LLM output is malformed.
        The raw output is included for debugging and analysis.
        """
        return {
            "intent": "unknown",
            "cve_id": None,
            "software": None,
            "severity": None,
            "weakness": None,
            "wants_mitigation": False,
            "raw_output": raw,
        }