def explain_vulnerability(cve: dict) -> dict:
    """
    Build a derived analysis object from structured CVE data.

    This function does not call an LLM.
    It creates a compact, API-friendly summary from the parsed NVD fields.
    """

    description = cve.get("description", "")
    products = cve.get("product_names", [])
    vendor = cve.get("vendor")
    severity = cve.get("severity", "Unknown")
    score = cve.get("score", "N/A")
    weaknesses = cve.get("weaknesses", [])
    references = cve.get("references", [])

    mitigation_keywords = [
        "patch",
        "upgrade",
        "update",
        "fix",
        "workaround",
        "mitigation",
    ]

    mitigation_available = any(
        keyword in description.lower()
        for keyword in mitigation_keywords
    )

    return {
        "severity_level": severity,
        "score": score,
        "affected_products": products,
        "vendor": vendor,
        "weaknesses": weaknesses,
        "reference_count": len(references),
        "risk_summary": description,
        "mitigation_available": mitigation_available,
    }