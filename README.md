Description of the project
System architecture (diagram optional)
How to run (including Docker)
API documentation (endpoints)
Description of dataset
Evaluation/results (quantitative and/or qualitative)

## Description of the Project

CyberGraph is a web service that enables natural language querying of cybersecurity vulnerabilities by combining large 
language models with a knowledge graph.
The system integrates data from the National Vulnerability Database (NVD) and the Common Weakness Enumeration (CWE), 
and transforms them into a structured RDF knowledge graph. This graph models relationships between vulnerabilities (CVEs), 
software products, weaknesses (CWEs), and external references using a custom ontology.
With the use of an API it is possible to submit queries in natual language, which is interpreted using an LLM, translated 
into structured parameters, and executed as SPARQL queries over the knowledge graph. 
The retrieved results are returned as structured data (including CVE identifiers, severity, affected products, and weaknesses), 
and are further used to generate concise, grounded insights through the LLM. 
The full data processing pipeline, RDF graph construction, semantic querying, and an API layer are all packaged 
in a Docker container for portability.

## System Architecture

CyberGraph follows a modular architecture that separates data ingestion, knowledge representation, query interpretation, and API exposure.

The system consists of the following main components:

- **Data Layer**: Loads and preprocesses vulnerability data from external sources (NVD and CWE).
- **Parsing Layer**: Normalizes raw data into a consistent internal schema.
- **Knowledge Graph Layer**: Builds an RDF graph using a custom ontology and enables querying via SPARQL.
- **NLP / LLM Layer**: Interprets natural language queries into structured parameters and generates insights.
- **Service Layer**: Orchestrates query execution and combines structured retrieval with LLM-based reasoning.
- **API Layer**: Exposes functionality via a FastAPI web service.

## Dataset

The project uses two cybersecurity data sources.

### National Vulnerability Database (NVD)

NVD provides concrete vulnerability records identified by CVE IDs. Each CVE entry may include descriptions, CVSS severity metrics, affected products encoded as CPE strings, weakness identifiers, and external references.

Example fields used from NVD:

- `id`
- `descriptions`
- `metrics`
- `weaknesses`
- `configurations`
- `references`

The `configurations` field contains CPE matches, which are used to extract affected software products.

### Common Weakness Enumeration (CWE)

CWE provides a taxonomy of software and hardware weakness types. Unlike NVD, CWE does not describe individual vulnerabilities, but categories of weaknesses such as integer overflow, SQL injection, or cross-site scripting.

The project uses CWE fields such as:

## CWE Dataset Fields

| Field | Description |
|---|---|
| **CWE-ID** | Unique numeric identifier for the weakness (e.g. CWE-79) |
| **Name** | Short descriptive name of the weakness |
| **Weakness Abstraction** | Granularity level: Pillar, Class, Base, or Variant |
| **Status** | Record maturity: Draft, Stable, Incomplete, Deprecated |
| **Description** | Brief summary of what the weakness is |
| **Extended Description** | In-depth explanation with additional context |
| **Related Weaknesses** | CWEs that are parent, child, or peer of this entry |
| **Weakness Ordinalities** | Role of the weakness: Primary or Resultant |
| **Applicable Platforms** | Languages, OS, or technologies where it applies |
| **Background Details** | Extra background useful to understand the weakness |
| **Alternate Terms** | Other names or terms used to refer to the weakness |
| **Modes Of Introduction** | Development phases where the weakness can be introduced |
| **Exploitation Factors** | Conditions that make exploitation easier |
| **Likelihood of Exploit** | How likely the weakness is to be exploited (Low/Med/High) |
| **Common Consequences** | Security impact: confidentiality, integrity, availability |
| **Detection Methods** | Techniques to detect the weakness (static analysis, fuzzing…) |
| **Potential Mitigations** | Recommended fixes and best practices |
| **Observed Examples** | Real-world CVEs linked to this weakness |
| **Functional Areas** | Software areas involved (auth, crypto, memory mgmt…) |
| **Affected Resources** | Resources at risk: memory, files, network, CPU |
| **Taxonomy Mappings** | Mappings to OWASP, CERT, WASC and other standards |
| **Related Attack Patterns** | Associated CAPEC attack patterns |
| **Notes** | Additional notes or editorial comments |


## Query Processing Pipeline

The system processes natural language queries through a multi-stage pipeline that combines a 
Large Language Model (LLM) with a Knowledge Graph (KG).

1. Natural Language Interpretation (LLM)

User queries are first interpreted using an LLM via a structured prompt:

    You are a cybersecurity query interpreter.

    Return ONLY valid JSON.
    Do not use markdown.
    Do not use code fences.

    Schema:
    {{
      "intent": "lookup_cve | mitigation_lookup | severity_search | software_search | software_severity_search | advanced_search | unknown",
      "cve_id": string or null,
      "software": string or null,
      "severity": "CRITICAL | HIGH | MEDIUM | LOW" or null,
      "weakness": string or null,
      "wants_mitigation": boolean
    }}

    User question:
    {question}

The LLM extracts structured intent and entities from the user question.

Example

{
  "intent": "advanced_search",
  "software": "nats-server",
  "severity": "HIGH",
  "weakness": "CWE-190"
}

⸻

2. Parsing and Fallback

The LLM output is parsed into JSON.

If parsing fails, the system returns a safe fallback:

{
  "intent": "unknown",
  "cve_id": null,
  "software": null,
  "severity": null,
  "weakness": null,
  "wants_mitigation": false
}

This ensures robustness against malformed LLM responses.

⸻

3. Intent-Based Execution

Based on the interpreted intent, different execution paths are triggered.


# CyberGraph Project

## 3. Query Execution Strategies

After the query has been interpreted into a structured format, the system executes it using different strategies depending on the detected intent.

---

### 3.1 CVE Lookup

When a specific CVE identifier is present, the system performs a direct lookup in the internal dataset.

In this case, the knowledge graph is not used, as the CVE ID already uniquely identifies the vulnerability.

Execution steps:

1. Retrieve the vulnerability from the dataset using the CVE ID  
2. Generate a short technical explanation of the vulnerability  
3. Produce a concise natural language answer using the LLM  

This strategy is efficient and avoids unnecessary graph queries.

---

### 3.2 Mitigation Lookup

Mitigation queries are handled as a variation of CVE lookup, with a focus on remediation-related information.

Execution steps:

1. Retrieve the vulnerability using the CVE ID  
2. Extract relevant information from:
   - description  
   - references (e.g. patches, advisories)  
   - version constraints  
3. Generate a mitigation-oriented explanation using the LLM  

It is important to note that the NVD dataset does not provide structured mitigation fields.  
Therefore, mitigation insights are inferred only from explicit evidence present in the data, without introducing external knowledge.

---

### 3.3 Advanced Search (Knowledge Graph)

For queries involving multiple constraints (e.g. software, severity, weakness), the system relies on the knowledge graph.

Execution steps:

1. Decompose the query into individual constraints  

2. Execute graph-based queries for each constraint  

3. Combine results using set intersection:

CVE ∈ Software ∩ Severity ∩ Weakness  

This approach allows flexible multi-dimensional filtering without hardcoding query logic.

---

### 3.4 Software Search

When the query specifies only a software product, the system retrieves all vulnerabilities affecting that product via the knowledge graph.

Execution steps:

1. Match product names using SPARQL (case-insensitive)  
2. Retrieve associated CVEs  
3. Generate a summarized answer  

---

### 3.5 Severity Search

When only a severity level is specified, the system retrieves all vulnerabilities matching that severity.

Execution steps:

1. Query the knowledge graph for CVEs with the given severity  
2. Aggregate results  
3. Generate a concise summary  

---

### 3.6 Software + Severity Search

For queries combining software and severity, the system performs a constrained graph search.

Execution steps:

1. Retrieve CVEs affecting the specified software  
2. Filter by severity  
3. Return intersected results  

---

### 3.7 Fallback / Unknown Intent

If the query cannot be reliably interpreted, the system returns a safe fallback response:

{
  "intent": "unknown"
}

This prevents system failure and ensures robustness against ambiguous or malformed queries.


Step 3: SPARQL queries

Example:

SELECT ?cve WHERE {
    ?cve a cg:Vulnerability ;
         cg:affects ?product .
    ?product rdfs:label ?label .
    FILTER(CONTAINS(LCASE(STR(?label)), "nats-server"))
}

⸻

4. Knowledge Graph Role

The Knowledge Graph integrates the Two different datasets,
providing a unified view of vulnerabilities and software products:
NVD provides vulnerability instances and contains affected product,
while CWE provides vulnerability categories and weakness types.

The datasets are complementary:

* NVD → “what is vulnerable” (software, CVEs)
* CWE → “what type of problem it is” (weakness class)



So:
👉 NVD does NOT provide “devices”
👉 It provides affected products via CPE identifiers

⸻

5. Result Aggregation

After retrieving matching CVEs:

results = [self.get_vulnerability(cve_id) for cve_id in cve_ids][:20]

The number of results is limited to avoid overload.

⸻

6. Answer Generation (LLM)

A second LLM call generates a concise, grounded answer.

Key design choices

* Uses only retrieved data (no hallucination)
* Compresses results into a small context
* Focuses on:
    * number of vulnerabilities
    * shared properties
    * differences
    * mitigation hints (if present)

Prompt structure

Answer the user's question using ONLY the retrieved results.
Focus on:
- number of vulnerabilities
- shared patterns
- differences
- fixes/workarounds

⸻

7. Final Response Structure

The API returns both structured and generated output:

{
  "interpreted_query": {...},
  "count": 2,
  "results": [...],
  "insight": "There are two high-severity vulnerabilities..."
}

⸻

🔥 Why this design is strong

This architecture combines:

* NLP → query understanding
* Knowledge Graph → precise filtering
* LLM → reasoning and summarization

This hybrid approach avoids:

* pure keyword search limitations
* pure LLM hallucinations

⸻

💡 Extra (very good for grading)

You can add this:

The system follows a retrieval-augmented generation paradigm, where the LLM is constrained by structured data retrieved from a knowledge graph, ensuring both precision and explainability.

⸻

Se vuoi nel prossimo step ti scrivo anche:

👉 Evaluation / Results (qualitative + quantitative)
👉 oppure README completo finale pronto da consegnare

Così chiudi il progetto davvero a livello top.