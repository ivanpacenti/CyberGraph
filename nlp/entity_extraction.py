import re


def extract_cve(text: str) -> list[str]:
    """
    Extract valid CVE identifiers according to MITRE format.

    Format:
    CVE-YYYY-NNNN... (4+ digits)
    """
    pattern = r"CVE-\d{4}-\d{4,7}"
    return re.findall(pattern, text)