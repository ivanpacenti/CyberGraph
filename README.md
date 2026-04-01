### Mapping Cybersecurity Threats, Vulnerabilities and Mitigations using NLP, Knowledge Graphs and LLMs

---

## Overview

This will be a web service that allows users to explore cybersecurity vulnerabilities through natural language queries. 
It will combines three core technologies:

- **NLP** — entity extraction and information parsing from unstructured text
- **Knowledge Graphs** — structured representation of CVE data and relationships
- **LLMs** — natural language interaction and answer generation

Users can query vulnerabilities by CVE identifier, discover relationships between vulnerabilities and affected software, 
retrieve mitigation strategies, and ask freeform questions in natural language.

---

## Tech Stack

| Layer | Tools |
|---|---|
| Backend | Python, FastAPI |
| NLP | spaCy or LLM-based entity recognition |
| Knowledge Graph | RDFLib (RDF), SPARQL |
| LLM | CampusAI API |
| Infrastructure | Docker |

---

## Data

### Sources
- **NVD** — National Vulnerability Database JSON feeds

### Knowledge Graph Structure

Data is processed into RDF triples of the form `(subject, predicate, object)`:

```
(CVE-2021-44228)  —affects→       (Apache Log4j)
(CVE-2021-44228)  —has_severity→  (Critical)
(CVE-2021-44228)  —mitigated_by→  (Patch 2.15.0)
```
---

### NLP Structure

The NLP component will include:
- Named Entity Recognition (NER) for identifying CVE identifiers, software names and severity levels
- Rule-based or LLM-based information extraction for mapping text into structured triples
---

## API Reference

**Base path:** `/api/v1`

---

### `GET /vulnerabilities/{cve_id}`
Returns structured information about a specific vulnerability.

---

### `GET /software/{name}/vulnerabilities`
Returns all vulnerabilities affecting a given software.

---

### `GET /attack-types/{type}/vulnerabilities`
Returns vulnerabilities associated with a specific attack type.

---

### `POST /query`
Natural language query interface. Interprets the question and retrieves relevant data from the knowledge graph.

**Request**
```json
{
  "question": "What vulnerabilities affect Apache Log4j?"
}
```

**Response**
```json
{
  "results": ["CVE-2021-44228"],
  "explanation": "Apache Log4j is affected by critical vulnerabilities including Log4Shell."
}
```

---

### `POST /query` — mitigation lookup

**Request**
```json
{
  "question": "How to mitigate CVE-2021-44228?"
}
```

**Response**
```json
{
  "cve_id": "CVE-2021-44228",
  "mitigation": "Upgrade to Log4j version 2.15.0 or later",
  "severity": "Critical"
}
```

---

### `POST /extract`
Extracts entities and structured information from raw cybersecurity text.

**Request**
```json
{
  "text": "CVE-2021-44228 is a critical vulnerability in Apache Log4j."
}
```

**Response**
```json
{
  "entities": {
    "cve": ["CVE-2021-44228"],
    "software": ["Apache Log4j"],
    "severity": ["Critical"]
  }
}
```

---

## Testing

| Type | Scope |
|---|---|
| Unit tests | API endpoints |
| NLP tests | Entity extraction accuracy |
| KG tests | SPARQL query correctness |
| Integration tests | End-to-end query flow |

---

## Scope & Complexity

The project covers:

- NLP pipeline (extraction and entity recognition)
- Knowledge graph construction and SPARQL querying
- LLM integration with prompt engineering
- REST API implementation with FastAPI
- Docker containerization
- Test suite