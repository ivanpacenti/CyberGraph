### Mapping Cybersecurity Threats, Vulnerabilities and Mitigations using NLP, Knowledge Graphs and LLMs

---

## Overview

This is a web service for exploring cybersecurity vulnerabilities through natural language queries. 
It combines LLM-based interpretation, a structured knowledge graph, and real-world National Vulnerabilieties Databse (NVD)
data into a unified pipeline.

Users can:
- Query vulnerabilities by CVE, software, severity, or weakness type
- Perform multi-constraint searches (e.g. *HIGH severity + CWE-190 + nats-server*)
- Receive interpreted answers with natural language explanations

---

## Architecture

The system follows an LLM-centered pipeline:

```
User Query
    ↓
LLM Query Interpretation
    ↓
SPARQL Query (Knowledge Graph)
    ↓
Structured Data Retrieval
    ↓
LLM Answer Generation
```

This design pairs **symbolic reasoning** (Knowledge Graph) with **neural reasoning** (LLM) to support both precise 
lookups and flexible natural language interaction.

---

## Tech Stack

| Layer | Tools |
|---|---|
| Backend | Python, FastAPI |
| Data | NVD JSON feeds |
| NLP / LLM | CampusAI API |
| Knowledge Graph | RDFLib, SPARQL |
| Infrastructure | Docker |

---

## Data

**Source:** NVD (National Vulnerability Database) JSON feeds

Each vulnerability is parsed into:

| Field | Example |
|---|---|
| CVE ID | CVE-2019-13126 |
| Description | Integer overflow in NATS Server |
| Severity & score | HIGH / 9.8 |
| Weakness (CWE) | CWE-190 |
| Affected products | nats-server |
| References | NVD links |

---

## Knowledge Graph

Parsed data is stored as RDF triples:

```
(CVE-2019-13126)  —affects→       (nats-server)
(CVE-2019-13126)  —hasSeverity→   (HIGH)
(CVE-2019-13126)  —hasWeakness→   (CWE-190)
```

This enables SPARQL queries with multi-constraint filtering and graph-based reasoning across the dataset.

---

## NLP Pipeline

NLP is handled entirely through LLM-based query interpretation — no separate extraction pipeline.

The LLM identifies:
- **Intent** — lookup, search, mitigation, comparison
- **Entities** — CVE ID, software name, severity level, CWE

**Example:**

Input:
```json
{ "question": "Show high severity vulnerabilities affecting nats-server with CWE-190" }
```

LLM output:
```json
{
  "intent": "advanced_search",
  "software": "nats-server",
  "severity": "HIGH",
  "weakness": "CWE-190"
}
```

---

## API Reference

**Base path:** `/api/v1`

---

### `GET /vulnerabilities/{cve_id}`
Returns structured data for a specific vulnerability.

---

### `POST /query`
Main entry point for natural language interaction.

**Request**
```json
{
  "question": "What are high severity vulnerabilities affecting nats-server with CWE-190?"
}
```

**Response**
```json
{
  "interpreted_query": {
    "intent": "advanced_search",
    "software": "nats-server",
    "severity": "HIGH",
    "weakness": "CWE-190"
  },
  "count": 2,
  "results": [...],
  "insight": "Two HIGH severity vulnerabilities affecting nats-server were found..."
}
```

---

## Query Capabilities

| Type | Description |
|---|---|
| CVE lookup | Retrieve a specific vulnerability by ID |
| Severity search | Filter by severity level (LOW / MEDIUM / HIGH / CRITICAL) |
| Software search | Find all vulnerabilities affecting a product |
| Weakness search | Filter by CWE identifier |
| Advanced search | Combine multiple constraints in a single query |

---

## Project Structure

```
app/
├── main.py
├── data_loader.py
└── data_parser.py

models/
└── models.py

services/
├── vulnerability_service.py
├── query_interpreter.py
├── answer_generator.py
└── campus_ai_api.py

kg/
├── graph_builder.py
└── knowledge_graph_service.py

data/
└── NVD/
```

---

## Testing

| Method | Description |
|---|---|
| Swagger UI | Interactive testing via `/docs` |
| Manual API calls | Direct HTTP requests |
| Unit tests | Per-component validation (optional) |

---

## Scope & Complexity

This project and covers:

- LLM-based NLP pipeline (interpretation and answer generation)
- Knowledge graph construction and SPARQL querying
- REST API design with FastAPI
- Multi-step reasoning across LLM and KG layers
- Real-world cybersecurity data integration (NVD)