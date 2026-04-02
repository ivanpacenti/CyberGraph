def explain_vulnerability(cve: dict) -> dict:
    """
    Build a derived analysis object from structured CVE data.

    This function does not call an LLM.
    It creates a compact, API-friendly summary from the parsed NVD fields.
    """

    description = cve.get("description", "")
    products = cve.get("product_names", [])
    severity = cve.get("severity", "Unknown")
    score = cve.get("score", "N/A")
    weaknesses = cve.get("weaknesses", [])

    mitigation_available = False

    return {
        "severity_level": severity,
        "score": score,
        "affected_products": products,
        "weaknesses": weaknesses,
        "risk_summary": description,
        "mitigation_available": mitigation_available,
    }