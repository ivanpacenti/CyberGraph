def deduplicate(seq):
    return list(dict.fromkeys(seq))

def extract_product_names(products: list[str]) -> list[str]:
    names = set()

    for p in products:
        parts = p.split(":")
        if len(parts) > 4:
            vendor = parts[3].replace("_", " ").strip()
            product = parts[4].replace("_", " ").strip()

            if product and product != "*":
                names.add(product)

            if vendor and vendor != "*" and vendor != product:
                names.add(vendor)
                if product and product != "*":
                    names.add(f"{vendor} {product}")

    return sorted(names)

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

    references = list(dict.fromkeys(
        ref.get("url") for ref in cve.get("references", []) if ref.get("url")
    ))
    product_names = extract_product_names(products)

    products = deduplicate(products)
    product_names = deduplicate(product_names)
    references = deduplicate(references)

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
        "product_names": product_names,
        "references": references,
    }