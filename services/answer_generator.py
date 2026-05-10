from services.campus_ai_api import get_text_response


def generate_final_answer(
    question: str,
    interpreted_query: dict,
    results: list[dict],
) -> str:
    """
    Generate a concise natural-language answer grounded on retrieved CVE data.
    """

    import json

    if not results:
        return (
            "No matching vulnerabilities were found for the provided query."
        )

    compact_results = []

    for cve in results[:5]:
        compact_results.append({
            "id": cve.get("id"),
            "description": cve.get("description"),
            "severity": cve.get("severity"),
            "score": cve.get("score"),
            "vendor": cve.get("vendor"),
            "product_names": cve.get("product_names", []),
            "weaknesses": cve.get("weaknesses", []),
            "references": cve.get("references", [])[:2],
        })

    prompt = f"""
You are a cybersecurity assistant.

Answer the user's question using ONLY the retrieved results below.

Do not invent facts.
Do not mention information that is not present in the retrieved results.

Your answer should summarize:
- how many vulnerabilities matched
- the main shared characteristics
- notable severity levels
- affected products or vendors
- recurring weakness patterns
- any explicit mitigation or exposure details mentioned

User question:
{question}

Interpreted query:
{json.dumps(interpreted_query, ensure_ascii=False)}

Retrieved results:
{json.dumps(compact_results, ensure_ascii=False, indent=2)}

Instructions:
- Write 2 to 4 concise sentences.
- Use plain English.
- Do not use markdown.
- Do not output JSON.
"""

    return get_text_response(prompt, temperature=0.0).strip()