from __future__ import annotations

import re
from urllib.parse import quote

from rdflib import Graph, RDF, RDFS, Literal
from rdflib.namespace import XSD

from kg.ontology import (
    CG,
    CVE,
    PRODUCT,
    VENDOR,
    CWE,
    REF,
    SEVERITY,
    add_ontology,
)


def safe_uri_fragment(text: str) -> str:
    """
    convert arbitrary text into a safe uri fragment.

    rdf uri references cannot safely contain spaces or special characters,
    so the text is normalized and percent-encoded.
    """

    normalized = str(text).strip().lower()
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
    add a literal triple only if the value exists.

    this avoids inserting empty or null values into the graph.
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
    build an rdf knowledge graph from normalized nvd and cwe data.

    the graph models:
    - vulnerabilities
    - weaknesses
    - software products
    - vendors
    - references
    - severity levels

    entities are connected using rdf triples defined in the ontology.
    """

    graph = Graph()

    # load ontology schema into the rdf graph
    add_ontology(graph)

    cwe_data = cwe_data or {}

    # iterate over all normalized vulnerabilities
    for vulnerability in parsed_data:
        cve_id = vulnerability.get("id")

        if not cve_id:
            continue

        # create rdf node for the vulnerability
        cve_uri = CVE[safe_uri_fragment(cve_id)]

        graph.add((cve_uri, RDF.type, CG.Vulnerability))
        graph.add((cve_uri, RDFS.label, Literal(cve_id)))

        # preserve the original cve identifier
        # because uri fragments are normalized to lowercase
        graph.add((cve_uri, CG.cveId, Literal(cve_id)))

        # add vulnerability metadata as datatype properties
        add_literal_if_present(
            graph,
            cve_uri,
            CG.description,
            vulnerability.get("description"),
            datatype=XSD.string,
        )

        add_literal_if_present(
            graph,
            cve_uri,
            CG.publishedAt,
            vulnerability.get("published"),
            datatype=XSD.dateTime,
        )

        add_literal_if_present(
            graph,
            cve_uri,
            CG.lastModifiedAt,
            vulnerability.get("last_modified"),
            datatype=XSD.dateTime,
        )

        add_literal_if_present(
            graph,
            cve_uri,
            CG.hasScore,
            vulnerability.get("score"),
            datatype=XSD.decimal,
        )

        # create severity entity node
        # severity is represented as a graph object instead of plain text
        severity = vulnerability.get("severity")

        if severity:
            severity_uri = SEVERITY[safe_uri_fragment(severity)]

            graph.add((severity_uri, RDF.type, CG.SeverityLevel))
            graph.add((severity_uri, RDFS.label, Literal(severity)))

            graph.add((cve_uri, CG.hasSeverityLevel, severity_uri))

        # create vendor entity if available
        vendor_name = vulnerability.get("vendor")

        vendor_uri = None

        if vendor_name:
            vendor_uri = VENDOR[safe_uri_fragment(vendor_name)]

            graph.add((vendor_uri, RDF.type, CG.Vendor))
            graph.add((vendor_uri, RDFS.label, Literal(vendor_name)))

            graph.add((vendor_uri, CG.vendorName, Literal(vendor_name)))

        # create software product entities
        # vulnerabilities are linked to affected products
        for product_name in vulnerability.get("product_names", []):
            if not product_name:
                continue

            product_uri = PRODUCT[safe_uri_fragment(product_name)]

            graph.add((product_uri, RDF.type, CG.SoftwareProduct))
            graph.add((product_uri, RDFS.label, Literal(product_name)))

            graph.add((product_uri, CG.productName, Literal(product_name)))

            # graph relationship:
            # vulnerability -> affects -> product
            graph.add((cve_uri, CG.affects, product_uri))

            # graph relationship:
            # product -> hasVendor -> vendor
            if vendor_uri:
                graph.add((product_uri, CG.hasVendor, vendor_uri))

        # create weakness entities from cwe ids
        for weakness_id in vulnerability.get("weaknesses", []):
            weakness_id = weakness_id.strip()

            if not weakness_id:
                continue

            weakness_uri = CWE[safe_uri_fragment(weakness_id)]

            graph.add((weakness_uri, RDF.type, CG.Weakness))
            graph.add((weakness_uri, RDFS.label, Literal(weakness_id)))

            graph.add((weakness_uri, CG.cweId, Literal(weakness_id)))

            # graph relationship:
            # vulnerability -> hasWeakness -> cwe
            graph.add((cve_uri, CG.hasWeakness, weakness_uri))

            # enrich the weakness node using semantic cwe metadata
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
                    CG.weaknessDescription,
                    cwe_info.get("description"),
                    datatype=XSD.string,
                )

        # create reference entities from external urls
        for reference_url in vulnerability.get("references", []):
            if not reference_url:
                continue

            reference_uri = REF[safe_uri_fragment(reference_url)]

            graph.add((reference_uri, RDF.type, CG.Reference))
            graph.add((reference_uri, RDFS.label, Literal(reference_url)))

            graph.add(
                (
                    reference_uri,
                    CG.referenceUrl,
                    Literal(reference_url, datatype=XSD.anyURI),
                )
            )

            # graph relationship:
            # vulnerability -> hasReference -> external reference
            graph.add((cve_uri, CG.hasReference, reference_uri))

    return graph