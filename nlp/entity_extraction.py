import re


def extract_cve(text: str):
    return re.findall(r"CVE-\d{4}-\d+", text)
