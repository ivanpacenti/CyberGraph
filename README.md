## Description of the Project

This is a web service that enables natural language querying of cybersecurity vulnerabilities by combining large
language models with a knowledge graph.
The system integrates data from the National Vulnerability Database (NVD) and the Common Weakness Enumeration (CWE),
and transforms them into a structured knowledge graph that models relationships between vulnerabilities (CVEs),
software products, weaknesses (CWEs), and external references using a custom ontology.
With the use of an API it is possible to submit queries in natual language, which is interpreted using an LLM, translated
into structured parameters, and executed as SPARQL queries over the knowledge graph.
The retrieved results are returned as structured data (including CVE identifiers, severity, affected products, and weaknesses),
and are further used to generate concise, grounded insights through the LLM.
The full system is packaged in a Docker container for portability.

## System Architecture

This project is designed as a modular system, where each component is responsible for a specific part of the pipeline,
from data ingestion to query execution and response generation.

The architecture is organized into the following layers:

* Data Layer: responsible for loading vulnerability data from the NVD and the CWE datasets. It handles raw data ingestion and basic preprocessing.
* Parsing Layer: The parsing step transforms the raw input data into a consistent internal format. Since NVD and CWE have different structures, this layer normalizes the data so it can be used uniformly across the system.
* Knowledge Graph Layer: In this layer, the normalized data is converted into an RDF knowledge graph based on a custom ontology. It defines entities such as vulnerabilities, software products, and weaknesses, and enables querying through SPARQL.
* NLP / LLM Layer: This component handles natural language understanding. It takes user queries and translates them into structured parameters (intent, software, severity, etc.). It is also used later to generate concise, human-readable insights from the retrieved data.
* Service Layer: The service layer acts as the central coordinator of the system. Based on the interpreted query, it decides whether to perform a direct lookup or a knowledge graph query, and combines the retrieved data with LLM-based reasoning.
* API Layer: The API layer exposes the system through a FastAPI web service. It provides endpoints for querying vulnerabilities and serves as the entry point for user interaction.

![System Architecture](af.png "Architecture flowchat")

## Dataset

The project uses two cybersecurity data sources:

### National Vulnerability Database (NVD)

NVD provides concrete vulnerability records identified by CVE IDs. Each CVE entry may include descriptions,
CVSS severity metrics, affected products encoded as CPE strings, weakness identifiers, and external references.

Example fields used from NVD:


| Field                | Description                                                        |
| -------------------- | ------------------------------------------------------------------ |
| **id**               | Unique identifier of the vulnerability (CVE ID)                    |
| **descriptions**     | Textual descriptions of the vulnerability in different languages   |
| **metrics**          | CVSS metrics including severity, score, and attack characteristics |
| **weaknesses**       | Associated CWE identifiers describing the type of weakness         |
| **configurations**   | Affected systems expressed as CPE matches (products and versions)  |
| **references**       | External links such as advisories, patches, or reports             |
| **published**        | Date when the vulnerability was first published                    |
| **lastModified**     | Date of the latest update to the vulnerability record              |
| **vulnStatus**       | Current status of the vulnerability (e.g., Modified, Analyzed)     |
| **cveTags**          | Optional tags associated with the CVE entry                        |
| **sourceIdentifier** | Identifier of the organization that reported the vulnerability     |

The `configurations` field contains CPE matches, which are used to extract affected software products.

### Common Weakness Enumeration (CWE)

CWE provides a classification of software and hardware weakness types. 
Unlike NVD, it does not describe individual vulnerabilities, but categories of weaknesses such as integer overflow, 
SQL injection, or cross-site scripting.

The project uses CWE fields such as:

#### CWE Dataset Fields


| Field                       | Description                                                    |
| --------------------------- | -------------------------------------------------------------- |
| **CWE-ID**                  | Unique numeric identifier for the weakness (e.g. CWE-79)       |
| **Name**                    | Short descriptive name of the weakness                         |
| **Weakness Abstraction**    | Granularity level: Pillar, Class, Base, or Variant             |
| **Status**                  | Record maturity: Draft, Stable, Incomplete, Deprecated         |
| **Description**             | Brief summary of what the weakness is                          |
| **Extended Description**    | In-depth explanation with additional context                   |
| **Related Weaknesses**      | CWEs that are parent, child, or peer of this entry             |
| **Weakness Ordinalities**   | Role of the weakness: Primary or Resultant                     |
| **Applicable Platforms**    | Languages, OS, or technologies where it applies                |
| **Background Details**      | Extra background useful to understand the weakness             |
| **Alternate Terms**         | Other names or terms used to refer to the weakness             |
| **Modes Of Introduction**   | Development phases where the weakness can be introduced        |
| **Exploitation Factors**    | Conditions that make exploitation easier                       |
| **Likelihood of Exploit**   | How likely the weakness is to be exploited (Low/Med/High)      |
| **Common Consequences**     | Security impact: confidentiality, integrity, availability      |
| **Detection Methods**       | Techniques to detect the weakness (static analysis, fuzzing…) |
| **Potential Mitigations**   | Recommended fixes and best practices                           |
| **Observed Examples**       | Real-world CVEs linked to this weakness                        |
| **Functional Areas**        | Software areas involved (auth, crypto, memory mgmt…)          |
| **Affected Resources**      | Resources at risk: memory, files, network, CPU                 |
| **Taxonomy Mappings**       | Mappings to OWASP, CERT, WASC and other standards              |
| **Related Attack Patterns** | Associated CAPEC attack patterns                               |
| **Notes**                   | Additional notes or editorial comments                         |

# Query Processing Pipeline

## 1. Natural Language Interpretation (LLM)

User queries are first interpreted using an LLM via a structured prompt:

```json
You are a cybersecurity query interpreter.

Return ONLY valid JSON.
Do not use markdown.
Do not explain anything.
Do not use code fences.

Allowed intents:
- lookup_cve
- mitigation_lookup
- severity_search
- software_search
- weakness_search
- vendor_search
- advanced_search
- unknown

JSON schema:
{{
  "intent": string,
  "cve_id": string or null,
  "software": string or null,
  "vendor": string or null,
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | null,
  "weakness": string or null,
  "wants_mitigation": boolean
}}

Examples:

Question:
"Which critical vulnerabilities affect Apache products?"

Output:
{{
  "intent": "advanced_search",
  "cve_id": null,
  "software": "Apache",
  "vendor": null,
  "severity": "CRITICAL",
  "weakness": null,
  "wants_mitigation": false
}}

Question:
"Find SQL injection vulnerabilities"

Output:
{{
  "intent": "weakness_search",
  "cve_id": null,
  "software": null,
  "vendor": null,
  "severity": null,
  "weakness": "SQL injection",
  "wants_mitigation": false
}}

User question:
{question}
```

The LLM extracts structured intent and entities from the user question.

Example:

```json
{
      "intent": "advanced_search",
      "cve_id": "CVE-2019-13126",
      "software": "Apache HTTP Server",
      "vendor": "Apache",
      "severity": "HIGH",
      "weakness": "CWE-79",
      "wants_mitigation": true
    }
```

## 2. Parsing and Fallback

The LLM output is parsed into JSON.

If parsing fails, the system returns a safe fallback:

```json
     {
    "intent": "unknown",
    "cve_id": None,
    "software": None,
    "vendor": None,
    "severity": None,
    "weakness": None,
    "wants_mitigation": False,
    "raw_output": raw,
    }
```

## 3. Intent-Based Execution

Based on the interpreted intent, different execution paths are triggered:

### 3.1 CVE Lookup

When a specific CVE identifier is present, the system performs a direct lookup in the internal dataset.

In this case, the knowledge graph is not required, since the CVE identifier already uniquely identifies the vulnerability.

Execution steps:

1. Retrieve the vulnerability from the dataset using the CVE ID
2. Generate a short technical explanation of the vulnerability
3. Produce a concise natural language answer using the LLM



### 3.2 Mitigation Lookup

Mitigation queries are handled as a variation of CVE lookup, with a focus on remediation-related information.

Execution steps:

1. Retrieve the vulnerability using the CVE ID
2. Extract relevant information from descriptions and references
3. Generate a mitigation-oriented explanation using the LLM

It is important to note that the NVD dataset does not provide structured mitigation fields.
Therefore, mitigation insights are inferred only from explicit evidence present in the retrieved data.



### 3.3 Software Search

When the query specifies a software product, the system retrieves vulnerabilities affecting that product through the knowledge graph.

Execution steps:

1. Match software products using SPARQL queries
2. Retrieve associated vulnerabilities
3. Generate a summarized natural language answer



### 3.4 Vendor Search

The system also supports graph-based retrieval using software vendors.

Execution steps:

1. Match vendor entities in the knowledge graph
2. Traverse relationships between vendors, products, and vulnerabilities
3. Return matching CVEs and generate a concise summary

This demonstrates multi-hop traversal capabilities of the knowledge graph.



### 3.5 Severity Search

When a severity level is specified, the system retrieves vulnerabilities associated with that severity category.

Execution steps:

1. Query the knowledge graph for vulnerabilities linked to the requested severity entity
2. Aggregate matching results
3. Generate a concise summary



### 3.6 Weakness Search

Weakness-based queries use CWE entities stored in the knowledge graph.

Execution steps:

1. Match weakness identifiers or weakness names
2. Retrieve vulnerabilities connected through the hasWeakness relation
3. Generate a summarized answer

This allows semantic searches such as “SQL injection vulnerabilities” or “CWE-79 vulnerabilities”.



### 3.7 Advanced Search

For queries involving multiple constraints (e.g. software, vendor, severity, or weakness), the system relies on the knowledge graph.

Execution steps:

1. Decompose the query into structured constraints
2. Execute graph-based queries for each constraint
3. Combine the result sets using set intersection

Example:

```text
CVE ∈ Software ∩ Vendor ∩ Severity ∩ Weakness
```

This approach enables flexible multi-dimensional filtering without hardcoding query logic.



### 3.8 Fallback / Unknown Intent

If the query cannot be reliably interpreted, the system returns a safe fallback response:

```json
{
  "intent": "unknown"
}
```

This prevents system failures and ensures robustness against ambiguous or malformed queries.


## Answer Generation (LLM)

A second LLM call generates a concise and grounded answer.
The key design choices are the use of only retrieved data to avoid hallucination,
to compresses results into a small context and to focuses on the most important aspects.

Prompt structure:

```json
You are a cybersecurity assistant.

Answer the user's question using ONLY the retrieved results below.

Do not invent facts.
Do not mention information that is not present in the retrieved results.

Your answer should summarize:
- how many vulnerabilities matched
- the main shared characteristics
- notable severity levels
- affected products or vendors
- recurring weakness patterns
- any explicit mitigation or exposure details mentioned

User question:
{question}

Interpreted query:
{json.dumps(interpreted_query, ensure_ascii=False)}

Retrieved results:
{json.dumps(compact_results, ensure_ascii=False, indent=2)}

Instructions:
- Write 2 to 4 concise sentences.
- Use the same language as the question.
- Do not use markdown.
- Do not output JSON.
```

## Knowledge Graph and Ontology

The project makes use of a knowledge graph to integrate and structure vulnerability data coming from different sources.
As described previously, the graph combines information from the National Vulnerability Database (NVD) and the Common 
Weakness Enumeration (CWE).
The two datasets serve different but complementary purposes.
NVD provides *concrete vulnerability instances* identified by CVE IDs, including descriptions, severity scores, 
affected software products, vendors, and external references, while CWE defines a *classification of weakness types*, 
such as integer overflows, SQL injections, or cross-site scripting vulnerabilities. 
Rather than describing individual incidents, CWE models the underlying software weaknesses that can lead to vulnerabilities.
Instead of relying on a shared primary key, the integration is achieved through semantic relationships.
Each CVE entry in NVD is linked to one or more CWE identifiers through the `hasWeakness` relation.
This allows the system to connect individual vulnerabilities with broader weakness categories and enrich the 
vulnerability data with additional semantic information.
A custom lightweight ontology was defined to model the cybersecurity domain.
The ontology is intentionally simple and focused on the project requirements, while still enabling graph-based retrieval 
and semantic querying.

The main classes include:

* `Vulnerability`, representing CVE entries from NVD
* `SoftwareProduct`, derived from CPE information in NVD
* `Vendor`, representing software vendors when available
* `Weakness`, representing CWE entries
* `Reference`, representing advisories, patches, or external reports
* `SeverityLevel`, representing severity categories such as HIGH or CRITICAL

These entities are connected through object properties such as:

* `affects`, linking a vulnerability to an affected software product
* `hasVendor`, linking a software product to its vendor
* `hasWeakness`, linking a vulnerability to a CWE category
* `hasReference`, linking a vulnerability to external resources
* `hasSeverityLevel`, linking a vulnerability to a severity entity

The ontology also defines datatype properties used to attach literal metadata to entities, including:

* `cveId`
* `cweId`
* `productName`
* `vendorName`
* `hasScore`
* `description`
* `weaknessDescription`
* `publishedAt`
* `lastModifiedAt`

Severity is represented as a graph entity instead of a plain literal value, for allowing vulnerabilities to be connected 
semantically to shared severity categories in the graph.

![Knowledge Graph Example](kg_sample.svg "Knowledge Graph Example")



## API Endpoints

### 1. GET /

This endpoint acts as a simple health check to verify that the service is running correctly.

Response example:

```json
{
      "message": "CyberGraph API is running"
    }
```

### 2. GET /vulnerabilities/{cve-id}

This endpoint retrieves structured information for a specific vulnerability identified by its CVE ID.

Example:

```bash
GET /vulnerabilities/CVE-2019-13126
```

Behavior:

* Looks up the CVE directly in the internal dataset
* Returns all available structured fields (description, severity, products, etc.)
* Returns a 404 error if the CVE is not found

### 3. POST /query

This is the main entry point of the system. It allows users to submit queries in natural language.

Request body:

```json
{
      "question": "Show me high severity vulnerabilities affecting nats-server with CWE-190"
    }
```

The full query processing logic is described in the section [Query Processing Pipeline](#query-processing-pipeline)

Response example:

```json
{
      "interpreted_query": {
        "intent": "advanced_search",
        "cve_id": null,
        "software": "nats-server",
        "vendor": null,
        "severity": "HIGH",
        "weakness": "CWE-190",
        "wants_mitigation": false
      },
      "count": 2,
      "results": [...],
      "insight": "There are two high-severity vulnerabilities affecting nats-server..."
    }
```

## How to Run

### Environment Variables

The system currently uses CampusAI to access a Large Language Model.

However, the design is modular and it is possible to switch to a different LLM provider by modifying the `campus_ai_api` module.

To run the project, you must provide your API key using a `.env` file as shown below, in the root of the project:

```env
CAMPUSAI_API_KEY=your_api_key_here
CAMPUSAI_MODEL="Gemma 4"
CAMPUSAI_API_URL=https://api.campusai.compute.dtu.dk/v1
```

---

## Run Locally

1. Activate the virtual environment:

```bash
source .venv/bin/activate
```

2. Start the API server:

```bash
uvicorn app.main:app
```

3. Open in browser:

- API root: http://127.0.0.1:8000
- Swagger docs: http://127.0.0.1:8000/docs

---

### Run with Docker

From the project root:

### 1. Build the container

```bash
sudo docker-compose up --build
```

Make sure that the \`.env\` file is located in the root directory of the project.

I initially encountered several issues when copying the \`.env\` file after the container had already been created.

The problem was solved by creating a proper \`docker-compose.yml\` configuration file and delegating the environment management to Docker Compose.

After building and starting the container, the API will be available at:

```text
http://127.0.0.1:8000
```

---

## Run Tests

Install test dependencies (if not already installed):

```bash
pip install pytest
```

Run tests:

```bash
pytest
```

## Evaluation and Results

The system was mainly evaluated through manual testing and by checking whether the different components behaved as expected.
From a functional point of view, the API correctly handles different types of queries.

Simple queries, such as retrieving a specific CVE, always return the expected result directly from the dataset.

More complex queries, involving multiple constraints (e.g. software, severity, and weakness), were also tested and showed
that the knowledge graph is working correctly, since the results match the intersection of the specified filters.

The natural language interface works well for common query patterns: the LLM is generally able to correctly identify the
intent and extract the relevant parameters. For example, queries like “high severity vulnerabilities affecting nats-server 
with CWE-190” are correctly interpreted and translated into structured filters. 
However, more ambiguous or poorly phrased queries may lead to an “unknown” intent, which is handled safely by the fallback 
mechanism.

The generated insights are useful as a short summary of the results. Since the LLM is constrained to only use retrieved 
data, the answers remain consistent with the actual vulnerabilities and do not introduce incorrect information. 
The summaries typically highlight the number of results, shared characteristics, and relevant differences between vulnerabilities.
From a robustness perspective, the system behaves well even when the LLM output is not valid JSON. In these cases, the 
fallback logic prevents crashes and returns a safe response. This makes the system more reliable when dealing with 
unpredictable model outputs.
In terms of performance, the system handles a few thousand vulnerabilities without noticeable issues, as the graph is 
built in memory at startup. However, this approach would likely not scale to much larger datasets. For larger-scale use, 
a more efficient graph backend (such as **QLever**) would be preferable.