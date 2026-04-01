from fastapi import FastAPI, HTTPException

from app.data_loader import get_nvds
from app.data_parser import extract_nvd_info
from models.models import QueryRequest, ExtractRequest
from nlp.entity_extraction import extract_cve
from services.vulnerability_service import VulnerabilityService
from services.knowledge_graph_service import KnowledgeGraphService
from services.query_interpreter import interpret_query

app = FastAPI(title="CyberGraph API")

raw_data = get_nvds()
parsed_data = [extract_nvd_info(item) for item in raw_data]

kg_service = KnowledgeGraphService(parsed_data)
vulnerability_service = VulnerabilityService(parsed_data, kg_service)


@app.get("/")
def root():
    return {"message": "CyberGraph API is running"}


@app.get("/api/v1/vulnerabilities/{cve_id}")
def get_vulnerability(cve_id: str):
    cve = vulnerability_service.get_vulnerability(cve_id)
    if not cve:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return cve


@app.post("/api/v1/query")
def query(request: QueryRequest):
    return vulnerability_service.handle_query(request.question)


@app.post("/api/v1/extract")
def extract(request: ExtractRequest):
    interpreted = interpret_query(request.text)
    found_cves = extract_cve(request.text)

    return {
        "entities": {
            "cve": found_cves,
            "software": interpreted.get("software"),
            "severity": interpreted.get("severity"),
        },
        "interpreted_query": interpreted,
    }