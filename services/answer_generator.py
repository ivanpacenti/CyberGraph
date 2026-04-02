from services.campus_ai_api import get_text_response


def generate_final_answer(question: str, interpreted_query: dict, results: list[dict]) -> str:
    """
    Generate a concise answer that adds value beyond listing raw results.
    """

    import json

    compact_results = []
    for cve in results[:5]:
        compact_results.append({
            "id": cve.get("id"),
            "description": cve.get("description"),
            "severity": cve.get("severity"),
            "score": cve.get("score"),
            "product_names": cve.get("product_names", []),
            "weaknesses": cve.get("weaknesses", []),
            "references": cve.get("references", [])[:2],
        })

    prompt = f"""
You are a cybersecurity assistant.

Answer the user's question using ONLY the retrieved results below.
Do not invent facts.

Your answer must add value beyond simply repeating the raw results.
Focus on:
- the number of matching vulnerabilities
- the main shared properties
- important differences between the results
- any explicit fix, workaround, or exposure detail mentioned in the descriptions

User question:
{question}

Interpreted query:
{json.dumps(interpreted_query, ensure_ascii=False)}

Retrieved results:
{json.dumps(compact_results, ensure_ascii=False, indent=2)}

Write 2 to 4 short sentences in plain English.
Do not use markdown.
"""
    return get_text_response(prompt, temperature=0.0).strip()