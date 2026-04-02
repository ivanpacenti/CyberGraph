# CyberGraph
### Mapping Cybersecurity Threats, Vulnerabilities and Mitigations using NLP, Knowledge Graphs and LLMs

---

## Overview

CyberGraph is a web service that enables users to explore cybersecurity vulnerabilities through natural language queries.

The system combines three core technologies:

- **NLP** — extracting structured information from user queries
- **Knowledge Graphs** — representing vulnerabilities, software, and relationships as RDF triples
- **LLMs** — query interpretation and explanation generation

Unlike simple keyword-based systems, the service uses an LLM as a query interpreter and orchestrator, translating natural language into structured intents that guide data retrieval and reasoning.

Users can:

- Query vulnerabilities using natural language
- Retrieve structured vulnerability data (CVE)
- Explore relationships between vulnerabilities and affected software
- Receive explanations and actionable advice grounded in real data

---

## System Architecture

The system follows a modular pipeline:

```
User Query (Natural Language)
        ↓
LLM Interpretation
  · Extracts intent (lookup, severity search, mitigation)
  · Identifies entities (CVE ID, software, severity)
        ↓
Service Layer
  · Routes query to appropriate logic
  · Combines structured retrieval and filtering
        ↓
Knowledge Graph (RDF)
  · Stores relationships between vulnerabilities, products, and properties
  · Enables graph-based queries via SPARQL
        ↓
LLM Explanation Layer
  · Generates human-readable explanations and recommendations
```

This architecture ensures that:

- The LLM is used for interpretation and generation
- All factual data is grounded in NVD structured data and the knowledge graph

---

## Tech Stack

| Layer | Tools |
|---|---|
| Backend | Python, FastAPI |
| NLP | Regex + LLM-based interpretation |
| Knowledge Graph | RDFLib (RDF), SPARQL |
| LLM | CampusAI API |
| Infrastructure | Docker |

---

## Data

### Source

- **NVD** — National Vulnerability Database JSON feeds

### Processing

NVD data is parsed and transformed into structured objects and RDF triples. The knowledge graph is built dynamically at application startup using RDFLib.

Example triples:

```
(CVE-2005-0012)  —hasSeverity→  "HIGH"
(CVE-2005-0012)  —affects→      "dillo"
(CVE-2005-0012)  —hasWeakness→  "CWE-190"
```

---

## NLP & LLM Pipeline

The system implements a hybrid NLP pipeline with four stages.

### 1. Query Interpretation (LLM)

The LLM converts user queries into structured JSON:

```json
{
  "intent": "mitigation_lookup",
  "cve_id": "CVE-2019-13126",
  "software": null,
  "severity": null,
  "wants_mitigation": true
}
```

### 2. Entity Extraction

- CVE identifiers extracted via regex
- Additional entities inferred by the LLM

### 3. Execution Layer

Based on the interpreted intent, the system:

- Retrieves data from the indexed NVD dataset
- Applies filters (severity, software)
- Queries the knowledge graph when relevant

### 4. Explanation & Advice (LLM)

The LLM generates structured explanations and defensive recommendations grounded in the retrieved data.

---

## API Reference

**Base path:** `/api/v1`

---

### `GET /vulnerabilities/{cve_id}`

Returns structured information about a specific vulnerability.

---

### `POST /query`

Natural language interface powered by LLM + structured retrieval.

**Request**
```json
{
  "question": "How to mitigate CVE-2019-13126?"
}
```

**Response**
```json
{
  "interpreted_query": {
    "intent": "mitigation_lookup",
    "cve_id": "CVE-2019-13126"
  },
  "result": { "..." : "..." },
  "explanation": "...",
  "advice": "..."
}
```

---

### `POST /extract`

Extracts structured entities from raw cybersecurity text.

---

## Testing

| Type | Scope |
|---|---|
| Unit tests | API endpoints |
| NLP tests | Query interpretation and entity extraction |
| KG tests | RDF graph and SPARQL queries |
| Integration tests | End-to-end query pipeline |

---

## Scope & Complexity

The project integrates multiple components from the course:

- NLP for information extraction and query understanding
- Knowledge graphs (RDF + SPARQL)
- Large language models for interpretation and generation
- Web services (FastAPI)
- Data engineering (NVD parsing)
- System integration and orchestration

---

## Key Design Choices

- **LLM as orchestrator** — not a fallback, but the primary query interpreter
- **Structured data as source of truth** — LLM never invents facts
- **Hybrid pipeline** — LLM handles flexibility, deterministic logic handles correctness
- **Separation of concerns** — service layer decouples routing from retrieval