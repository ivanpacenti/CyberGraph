#!/usr/bin/env python3

from rdflib import Graph, Literal, RDF, RDFS
from rdflib.namespace import XSD
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches

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


def create_sample_graph() -> Graph:
    """
    create a small rdf graph showing the main cybergraph relationships.
    """

    graph = Graph()
    add_ontology(graph)

    cve_uri = CVE["cve-2023-12345"]
    product_uri = PRODUCT["apache-http-server"]
    vendor_uri = VENDOR["apache"]
    weakness_uri = CWE["cwe-79"]
    severity_uri = SEVERITY["high"]
    ref_uri = REF["example-advisory"]

    graph.add((cve_uri, RDF.type, CG.Vulnerability))
    graph.add((cve_uri, RDFS.label, Literal("CVE-2023-12345")))
    graph.add((cve_uri, CG.cveId, Literal("CVE-2023-12345")))
    graph.add((cve_uri, CG.hasScore, Literal("7.5", datatype=XSD.decimal)))
    graph.add((cve_uri, CG.description, Literal("sample cross-site scripting vulnerability.")))

    graph.add((severity_uri, RDF.type, CG.SeverityLevel))
    graph.add((severity_uri, RDFS.label, Literal("HIGH")))
    graph.add((cve_uri, CG.hasSeverityLevel, severity_uri))

    graph.add((vendor_uri, RDF.type, CG.Vendor))
    graph.add((vendor_uri, RDFS.label, Literal("Apache")))
    graph.add((vendor_uri, CG.vendorName, Literal("Apache")))

    graph.add((product_uri, RDF.type, CG.SoftwareProduct))
    graph.add((product_uri, RDFS.label, Literal("Apache HTTP Server")))
    graph.add((product_uri, CG.productName, Literal("Apache HTTP Server")))
    graph.add((product_uri, CG.hasVendor, vendor_uri))
    graph.add((cve_uri, CG.affects, product_uri))

    graph.add((weakness_uri, RDF.type, CG.Weakness))
    graph.add((weakness_uri, RDFS.label, Literal("CWE-79")))
    graph.add((weakness_uri, CG.cweId, Literal("CWE-79")))
    graph.add((weakness_uri, CG.weaknessDescription, Literal("Cross-site scripting weakness.")))
    graph.add((cve_uri, CG.hasWeakness, weakness_uri))

    graph.add((ref_uri, RDF.type, CG.Reference))
    graph.add((ref_uri, RDFS.label, Literal("Advisory Link")))
    graph.add((ref_uri, CG.referenceUrl, Literal("https://example.com/advisory", datatype=XSD.anyURI)))
    graph.add((cve_uri, CG.hasReference, ref_uri))

    return graph


def node_label(graph: Graph, node) -> str:
    label = graph.value(node, RDFS.label)

    if label:
        return str(label)

    value = str(node)

    if "/" in value:
        return value.rstrip("/").split("/")[-1]

    return value


def predicate_label(predicate) -> str:
    return str(predicate).rstrip("/").split("/")[-1]


def visualize_graph(graph: Graph) -> None:
    G = nx.DiGraph()

    visible_predicates = {
        CG.affects,
        CG.hasVendor,
        CG.hasWeakness,
        CG.hasReference,
        CG.hasSeverityLevel,
    }

    edge_labels = {}

    for subject, predicate, obj in graph:
        if predicate not in visible_predicates:
            continue

        s_label = node_label(graph, subject)
        o_label = node_label(graph, obj)
        p_label = predicate_label(predicate)

        G.add_edge(s_label, o_label)
        edge_labels[(s_label, o_label)] = p_label

    node_colors = []

    for node in G.nodes:
        node_lower = node.lower()

        if node.startswith("CVE"):
            node_colors.append("red")
        elif "apache http" in node_lower:
            node_colors.append("skyblue")
        elif node_lower == "apache":
            node_colors.append("violet")
        elif node.startswith("CWE") or "scripting" in node_lower:
            node_colors.append("lightgreen")
        elif node == "HIGH":
            node_colors.append("gold")
        elif "advisory" in node_lower:
            node_colors.append("orange")
        else:
            node_colors.append("lightgray")

    plt.figure(figsize=(12, 7), facecolor="none")

    pos = nx.spring_layout(G, seed=42, k=1.2)

    nx.draw(
        G,
        pos,
        with_labels=True,
        node_color=node_colors,
        node_size=2600,
        font_size=9,
        font_weight="bold",
        arrows=True,
        arrowsize=20,
    )

    nx.draw_networkx_edge_labels(
        G,
        pos,
        edge_labels=edge_labels,
        font_size=8,
    )

    legend_elements = [
        mpatches.Patch(
            color="red",
            label="Vulnerability (CVE) - NVD Dataset"
        ),
        mpatches.Patch(
            color="skyblue",
            label="Software Product - NVD Dataset"
        ),
        mpatches.Patch(
            color="violet",
            label="Vendor - NVD Dataset"
        ),
        mpatches.Patch(
            color="lightgreen",
            label="Weakness (CWE) - CWE Dataset"
        ),
        mpatches.Patch(
            color="gold",
            label="Severity Level - NVD Dataset"
        ),
        mpatches.Patch(
            color="orange",
            label="External Reference - NVD Dataset"
        ),
        mpatches.Patch(
            color="lightgray",
            label="Literal Attributes"
        ),
    ]

    plt.legend(handles=legend_elements, loc="best")
    plt.title("CyberGraph Knowledge Graph Sample")
    plt.axis("off")
    plt.tight_layout()

    plt.savefig("kg_sample.png", dpi=300, bbox_inches="tight", transparent=True)
    plt.savefig("kg_sample.svg", bbox_inches="tight", transparent=True)

    plt.show()


if __name__ == "__main__":
    sample_graph = create_sample_graph()

    print(f"Sample graph has {len(sample_graph)} triples")

    visualize_graph(sample_graph)

    print("Visualization saved as 'kg_sample.png' and 'kg_sample.svg'")
