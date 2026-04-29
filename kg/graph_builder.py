from __future__ import annotations

import re
from urllib.parse import quote

from rdflib import Graph, RDF, RDFS, Literal, URIRef
from rdflib.namespace import XSD

from kg.ontology import CG, CVE, PRODUCT, CWE, add_ontology


def safe_uri_fragment(text: str) -> str:
    """
    Convert arbitrary text into a safe URI fragment.

    Product names and CWE labels may contain spaces, slashes, ampersands,
    or other characters that are not safe in RDF URIRefs. This function
    normalizes the text and percent-encodes unsafe characters.
    """
    normalized = text.strip().lower()
    normalized = normalized.replace("_", " ")
    normalized = re.sub(r"\s+", "-", normalized)

    return quote(normalized, safe="-")


def add_literal_if_present(
    graph: Graph,
    subject,
    predicate,
    value,
    datatype=None,
) -> None:
    """
    Add a literal triple only if the value is not empty.
    """
    if value is None or value == "":
        return

    if datatype:
        graph.add((subject, predicate, Literal(value, datatype=datatype)))
    else:
        graph.add((subject, predicate, Literal(value)))


def build_graph(
    parsed_data: list[dict],
    cwe_data: dict[str, dict] | None = None,
) -> Graph:
    """
    Build an RDF knowledge graph from normalized NVD data and CWE data.

    NVD provides vulnerability instances:
    - CVE ID
    - description
    - severity
    - score
    - affected products
    - references

    CWE provides semantic information about weaknesses:
    - CWE ID
    - weakness name
    - weakness description

    The resulting graph links CVEs to products, weaknesses and references
    using the CyberGraph ontology.
    """
    graph = Graph()
    add_ontology(graph)

    cwe_data = cwe_data or {}

    for vulnerability in parsed_data:
        cve_id = vulnerability.get("id")

        if not cve_id:
            continue

        cve_uri = CVE[cve_id]

        # CVE instance
        graph.add((cve_uri, RDF.type, CG.Vulnerability))
        graph.add((cve_uri, RDFS.label, Literal(cve_id)))

        # CVE data properties
        add_literal_if_present(
            graph,
            cve_uri,
            CG.description,
            vulnerability.get("description"),
        )

        add_literal_if_present(
            graph,
            cve_uri,
            CG.publishedAt,
            vulnerability.get("published"),
        )

        add_literal_if_present(
            graph,
            cve_uri,
            CG.lastModifiedAt,
            vulnerability.get("last_modified"),
        )

        add_literal_if_present(
            graph,
            cve_uri,
            CG.hasSeverity,
            vulnerability.get("severity"),
        )

        add_literal_if_present(
            graph,
            cve_uri,
            CG.hasScore,
            vulnerability.get("score"),
            datatype=XSD.float,
        )

        # Affected software products
        for product_name in vulnerability.get("product_names", []):
            product_uri = PRODUCT[safe_uri_fragment(product_name)]

            graph.add((product_uri, RDF.type, CG.SoftwareProduct))
            graph.add((product_uri, RDFS.label, Literal(product_name)))
            graph.add((cve_uri, CG.affects, product_uri))

        # Weaknesses / CWE links
        for weakness_id in vulnerability.get("weaknesses", []):
            weakness_id = weakness_id.strip()

            if not weakness_id:
                continue

            weakness_uri = CWE[safe_uri_fragment(weakness_id)]

            graph.add((weakness_uri, RDF.type, CG.Weakness))
            graph.add((weakness_uri, RDFS.label, Literal(weakness_id)))
            graph.add((cve_uri, CG.hasWeakness, weakness_uri))

            # Enrich weakness node with CWE datasource, if available
            cwe_info = cwe_data.get(weakness_id)

            if cwe_info:
                add_literal_if_present(
                    graph,
                    weakness_uri,
                    RDFS.label,
                    cwe_info.get("name"),
                )

                add_literal_if_present(
                    graph,
                    weakness_uri,
                    CG.description,
                    cwe_info.get("description"),
                )

        # External references
        for reference_url in vulnerability.get("references", []):
            if not reference_url:
                continue

            reference_uri = URIRef(reference_url)

            graph.add((reference_uri, RDF.type, CG.Reference))
            graph.add((cve_uri, CG.hasReference, reference_uri))

    return graph