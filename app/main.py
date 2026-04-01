from fastapi import FastAPI, HTTPException

from app.data_loader import get_nvds
from app.data_parser import extract_nvd_info
from models.models import QueryRequest, ExtractRequest
from nlp.entity_extraction import extract_cve
from services.explainer import explain_vulnerability
from services.query_interpreter import interpret_query

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


@app.post("/api/v1/query")
def query(request: QueryRequest):
    question = request.question.strip()

    # 1. regex-based CVE lookup
    found_cves = extract_cve(question)
    if found_cves:
        cve_id = found_cves[0]
        cve = cve_index.get(cve_id)

        if not cve:
            return {"error": f"{cve_id} not found"}

        explanation = explain_vulnerability(cve)

        return {
            "interpreted_intent": "lookup_cve",
            "cve_id": cve_id,
            "result": cve,
            "explanation": explanation,
        }

    # 2. fallback to LLM interpretation
    interpreted = interpret_query(question)

    intent = interpreted.get("intent")
    cve_id = interpreted.get("cve_id")
    software = interpreted.get("software")
    severity = interpreted.get("severity")

    if cve_id:
        cve = cve_index.get(cve_id)
        if cve:
            explanation = explain_vulnerability(cve)
            return {
                "interpreted_query": interpreted,
                "result": cve,
                "explanation": explanation,
            }

    if intent == "severity_search" and severity:
        results = [c for c in parsed_data if c.get("severity") == severity][:20]
        return {
            "interpreted_query": interpreted,
            "count": len(results),
            "results": results,
        }

    if intent == "software_search" and software:
        results = []
        software_lower = software.lower()

        for c in parsed_data:
            product_names = c.get("product_names", [])
            if any(software_lower in p.lower() for p in product_names):
                results.append(c)

        return {
            "interpreted_query": interpreted,
            "count": len(results),
            "results": results[:20],
        }

    return {
        "interpreted_query": interpreted,
        "message": "Could not answer query"
    }


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