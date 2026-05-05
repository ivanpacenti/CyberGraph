from fastapi import FastAPI, HTTPException

from app.data_loader import load_nvd, load_cwe
from app.data_parser import extract_nvd_info
from models.models import QueryRequest
from services.knowledge_graph_service import KnowledgeGraphService
from services.vulnerability_service import VulnerabilityService


app = FastAPI(
    title="CyberGraph API",
    description="Natural language interface for querying cybersecurity vulnerabilities using LLMs and knowledge graphs.",
    version="0.1.0",
)


# load external data sources
raw_nvd_data = load_nvd()
cwe_data = load_cwe()

# Normalize NVD data into the internal schema
parsed_vulnerabilities = [
    extract_nvd_info(item)
    for item in raw_nvd_data
]

# Build the knowledge graph using both NVD and CWE data
kg_service = KnowledgeGraphService(
    nvd_data=parsed_vulnerabilities,
    cwe_data=cwe_data,
)

# Service layer used by the API endpoints
vulnerability_service = VulnerabilityService(
    parsed_data=parsed_vulnerabilities,
    kg_service=kg_service,
)


@app.get("/")
def root() -> dict:
    """
    Health check endpoint.
    """
    return {"message": "CyberGraph API is running"}


@app.get("/vulnerabilities/{cve_id}")
def get_vulnerability(cve_id: str) -> dict:
    """
    Return structured information for a specific CVE.
    """
    cve = vulnerability_service.get_vulnerability(cve_id)

    if not cve:
        raise HTTPException(
            status_code=404,
            detail="Vulnerability not found",
        )

    return cve


@app.post("/query")
def query(request: QueryRequest) -> dict:
    """
    Natural language query endpoint.

    Pipeline:
    1. LLM interprets the user question
    2. Knowledge graph retrieves matching vulnerabilities
    3. LLM generates a grounded insight from the retrieved results
    """
    return vulnerability_service.handle_query(request.question)