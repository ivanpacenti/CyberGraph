import json
from pathlib import Path

NVD_PATH = Path("data/NVD")

def get_nvds():
    all_nvds = []

    for file in NVD_PATH.glob("*.json"):
        print(f"Loading {file}")
        with open(file) as f:
            data = json.load(f)
            all_nvds.extend(data["vulnerabilities"])
    print(f"Loaded {len(all_nvds)} NVD entries")
    return all_nvds