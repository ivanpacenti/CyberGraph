def extract_nvd_info(item):
    cve = item["cve"]

    cve_id = cve.get("id")
    published = cve.get("published")
    last_modified = cve.get("lastModified")
    status = cve.get("vulnStatus")

    description = None
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value")
            break

    severity = None
    score = None

    metrics = cve.get("metrics", {})
    if "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
        metric = metrics["cvssMetricV31"][0]
        severity = metric.get("cvssData", {}).get("baseSeverity") or metric.get("baseSeverity")
        score = metric.get("cvssData", {}).get("baseScore")
    elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
        metric = metrics["cvssMetricV30"][0]
        severity = metric.get("cvssData", {}).get("baseSeverity") or metric.get("baseSeverity")
        score = metric.get("cvssData", {}).get("baseScore")
    elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        metric = metrics["cvssMetricV2"][0]
        severity = metric.get("baseSeverity")
        score = metric.get("cvssData", {}).get("baseScore")

    weaknesses = []
    for w in cve.get("weaknesses", []):
        for desc in w.get("description", []):
            if desc.get("lang") == "en":
                weaknesses.append(desc.get("value"))

    products = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria")
                if criteria:
                    products.append(criteria)

    references = [ref.get("url") for ref in cve.get("references", []) if ref.get("url")]

    return {
        "id": cve_id,
        "published": published,
        "last_modified": last_modified,
        "status": status,
        "description": description,
        "severity": severity,
        "score": score,
        "weaknesses": weaknesses,
        "products": products,
        "references": references,
    }