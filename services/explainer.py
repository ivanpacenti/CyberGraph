def explain_vulnerability(cve: dict) -> str:
    description = cve.get("description", "")
    product = ", ".join(cve.get("product_names", [])) or "Unknown"
    severity = cve.get("severity", "Unknown")
    score = cve.get("score", "N/A")

    return f"""
Vulnerability Summary

CVE ID: {cve.get("id")}

Description:
{description}

Affected Product:
{product}

Severity:
{severity} (Score: {score})

Mitigation:
No explicit mitigation is provided in the structured data.
"""