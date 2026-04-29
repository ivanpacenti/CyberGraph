from rdflib import Graph, Namespace, RDF, RDFS, OWL, XSD, Literal

CG = Namespace("http://example.org/cybergraph/")
CVE = Namespace("http://example.org/cybergraph/cve/")
PRODUCT = Namespace("http://example.org/cybergraph/product/")
CWE = Namespace("http://example.org/cybergraph/cwe/")


def bind_namespaces(graph: Graph) -> None:
    graph.bind("cg", CG)
    graph.bind("cve", CVE)
    graph.bind("product", PRODUCT)
    graph.bind("cwe", CWE)
    graph.bind("rdf", RDF)
    graph.bind("rdfs", RDFS)
    graph.bind("owl", OWL)
    graph.bind("xsd", XSD)


def add_ontology(graph: Graph) -> None:
    bind_namespaces(graph)

    # Classes
    graph.add((CG.Vulnerability, RDF.type, OWL.Class))
    graph.add((CG.SoftwareProduct, RDF.type, OWL.Class))
    graph.add((CG.Weakness, RDF.type, OWL.Class))
    graph.add((CG.Reference, RDF.type, OWL.Class))

    graph.add((CG.Vulnerability, RDFS.label, Literal("Vulnerability")))
    graph.add((CG.SoftwareProduct, RDFS.label, Literal("Software Product")))
    graph.add((CG.Weakness, RDFS.label, Literal("Weakness")))
    graph.add((CG.Reference, RDFS.label, Literal("Reference")))

    # Object properties
    object_properties = [
        CG.affects,
        CG.hasWeakness,
        CG.hasReference,
    ]

    for prop in object_properties:
        graph.add((prop, RDF.type, OWL.ObjectProperty))

    # Data properties
    data_properties = [
        CG.hasSeverity,
        CG.hasScore,
        CG.description,
        CG.publishedAt,
        CG.lastModifiedAt,
    ]

    for prop in data_properties:
        graph.add((prop, RDF.type, OWL.DatatypeProperty))

    # Domains and ranges
    graph.add((CG.affects, RDFS.domain, CG.Vulnerability))
    graph.add((CG.affects, RDFS.range, CG.SoftwareProduct))

    graph.add((CG.hasWeakness, RDFS.domain, CG.Vulnerability))
    graph.add((CG.hasWeakness, RDFS.range, CG.Weakness))

    graph.add((CG.hasReference, RDFS.domain, CG.Vulnerability))
    graph.add((CG.hasReference, RDFS.range, CG.Reference))

    graph.add((CG.hasSeverity, RDFS.domain, CG.Vulnerability))
    graph.add((CG.hasScore, RDFS.domain, CG.Vulnerability))
    graph.add((CG.description, RDFS.domain, CG.Vulnerability))