from fastapi import FastAPI, HTTPException
from app.data_loader import get_nvds
from app.data_parser import extract_nvd_info

app = FastAPI(title="CyberGraph API")

raw_data = get_nvds()
parsed_data = [extract_nvd_info(item) for item in raw_data]

cve_index = {item["id"]: item for item in parsed_data if item.get("id")}


@app.get("/")
def root():
    return {"message": "CyberGraph API is running"}


@app.get("/api/v1/vulnerabilities/{cve_id}")
def get_vulnerability(cve_id: str):
    cve = cve_index.get(cve_id)
    if not cve:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return cve