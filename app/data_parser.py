from typing import List, Dict, Any


def deduplicate(seq: List[Any]) -> List[Any]:
    """
    Remove duplicates while preserving order.
    Uses dict insertion order (Python 3.7+).
    """
    return list(dict.fromkeys(seq))


def extract_product_names(products: List[str]) -> List[str]:
    """
    Extract human-readable product names from CPE strings.

    Example CPE:
    cpe:2.3:a:vendor:product:...

    Returns:
        Sorted list of:
        - product names
        - vendor names
        - "vendor product" combinations
    """
    names = set()

    for cpe in products:
        parts = cpe.split(":")

        # Ensure valid CPE format
        if len(parts) <= 4:
            continue

        vendor = parts[3].replace("_", " ").strip()
        product = parts[4].replace("_", " ").strip()

        # Add product name
        if product and product != "*":
            names.add(product)

        # Add vendor and combined name
        if vendor and vendor != "*" and vendor != product:
            names.add(vendor)

            if product and product != "*":
                names.add(f"{vendor} {product}")

    return sorted(names)


def extract_nvd_info(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize a raw NVD vulnerability entry into a unified internal schema.

    This function:
    - extracts relevant fields from NVD JSON
    - handles multiple CVSS versions
    - cleans and deduplicates data
    - prepares the data for Knowledge Graph ingestion

    Returns:
        Dict with normalized vulnerability fields
    """
    cve = item.get("cve", {})

    # --- Basic metadata ---
    cve_id = cve.get("id")
    published = cve.get("published")
    last_modified = cve.get("lastModified")
    status = cve.get("vulnStatus")

    # --- Description (prefer English) ---
    description = next(
        (d.get("value") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
        None
    )

    # --- Severity & score (handle multiple CVSS versions) ---
    severity = None
    score = None

    metrics = cve.get("metrics", {})

    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            metric = metrics[key][0]

            severity = (
                metric.get("cvssData", {}).get("baseSeverity")
                or metric.get("baseSeverity")
            )

            score = metric.get("cvssData", {}).get("baseScore")
            break  # stop at first available version

    # --- Weaknesses (CWE IDs) ---
    weaknesses = [
        desc.get("value")
        for w in cve.get("weaknesses", [])
        for desc in w.get("description", [])
        if desc.get("lang") == "en"
    ]

    # --- Products (CPEs) ---
    products = [
        match.get("criteria")
        for config in cve.get("configurations", [])
        for node in config.get("nodes", [])
        for match in node.get("cpeMatch", [])
        if match.get("criteria")
    ]

    # --- References (URLs) ---
    references = [
        ref.get("url")
        for ref in cve.get("references", [])
        if ref.get("url")
    ]

    # --- Derived fields ---
    product_names = extract_product_names(products)

    # --- Deduplication ---
    return {
        "id": cve_id,
        "published": published,
        "last_modified": last_modified,
        "status": status,
        "description": description,
        "severity": severity,
        "score": score,
        "weaknesses": deduplicate(weaknesses),
        "products": deduplicate(products),
        "product_names": deduplicate(product_names),
        "references": deduplicate(references),
    }