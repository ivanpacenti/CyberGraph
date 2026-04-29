import csv
import json
from pathlib import Path

# Root folders for data sources
NVD_PATH = Path("data/NVD")
CWE_PATH = Path("data/CWE/2000.csv")


def load_nvd() -> list[dict]:
    """
    Load and aggregate NVD vulnerability data from multiple JSON files.

    Returns:
        List of vulnerability entries in raw NVD format.

    Notes:
        - Each file contains a list under "vulnerabilities"
        - We flatten all files into a single list
        - This data will later be transformed into RDF triples
    """
    vulnerabilities = []

    for file in NVD_PATH.glob("*.json"):
        with open(file, encoding="utf-8") as f:
            data = json.load(f)

            # Each file contains a list of vulnerabilities
            vulnerabilities.extend(data.get("vulnerabilities", []))

    print(f"[NVD] Total entries loaded: {len(vulnerabilities)}")

    return vulnerabilities


def load_cwe() -> dict[str, dict]:
    """
    Load CWE (Common Weakness Enumeration) data from CSV.

    Returns:
        Dictionary indexed by CWE ID (e.g., 'CWE-190') with:
            - id
            - name
            - description

    Notes:
        - CWE provides a taxonomy (ontology-like structure) of weaknesses
        - Used to enrich NVD vulnerabilities with semantic meaning
        - Enables graph-based reasoning (e.g., grouping similar weaknesses)
    """
    cwe_dict = {}

    with open(CWE_PATH, encoding="utf-8") as f:
        reader = csv.DictReader(f)

        # Debug (optional): inspect column names if needed
        # print(reader.fieldnames)

        for row in reader:
            # Handle different possible column names
            raw_id = row.get("ID") or row.get("CWE-ID")

            if not raw_id:
                continue

            cwe_id = f"CWE-{raw_id}"

            cwe_dict[cwe_id] = {
                "id": cwe_id,
                "name": row.get("Name", ""),
                "description": row.get("Description", ""),
            }

    print(f"[CWE] Total entries loaded: {len(cwe_dict)}")

    return cwe_dict