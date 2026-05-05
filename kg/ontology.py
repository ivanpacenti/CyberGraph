# Ontology for CyberGraph Knowledge Graph
# This module defines the RDF ontology used to model cybersecurity vulnerabilities,
# software products, weaknesses, and references. It uses OWL (Web Ontology Language)
# to specify classes, object properties (relationships between entities), and
# datatype properties (attributes of entities).

from rdflib import Graph, Namespace, RDF, RDFS, OWL, XSD, Literal

# Define custom namespaces for the ontology
# CG: General CyberGraph namespace for classes and properties
# CVE: Namespace for CVE-specific entities (e.g., individual vulnerabilities)
# PRODUCT: Namespace for software product entities
# CWE: Namespace for CWE (Common Weakness Enumeration) entities
CG = Namespace("http://example.org/cybergraph/")
CVE = Namespace("http://example.org/cybergraph/cve/")
PRODUCT = Namespace("http://example.org/cybergraph/product/")
CWE = Namespace("http://example.org/cybergraph/cwe/")


def bind_namespaces(graph: Graph) -> None:
    # Bind namespace prefixes to the RDF graph for easier serialization and querying
    # This allows using short prefixes like 'cg:Vulnerability' instead of full URIs
    graph.bind("cg", CG)
    graph.bind("cve", CVE)
    graph.bind("product", PRODUCT)
    graph.bind("cwe", CWE)
    graph.bind("rdf", RDF)
    graph.bind("rdfs", RDFS)
    graph.bind("owl", OWL)
    graph.bind("xsd", XSD)


def add_ontology(graph: Graph) -> None:
    # Add the ontology definitions to the RDF graph
    bind_namespaces(graph)

    # Define OWL Classes (entity types in the knowledge graph)
    # These represent the main concepts: vulnerabilities, software products, weaknesses, and references
    graph.add((CG.Vulnerability, RDF.type, OWL.Class))
    graph.add((CG.SoftwareProduct, RDF.type, OWL.Class))
    graph.add((CG.Weakness, RDF.type, OWL.Class))
    graph.add((CG.Reference, RDF.type, OWL.Class))

    # Add human-readable labels to the classes for better interpretability
    graph.add((CG.Vulnerability, RDFS.label, Literal("Vulnerability")))
    graph.add((CG.SoftwareProduct, RDFS.label, Literal("Software Product")))
    graph.add((CG.Weakness, RDFS.label, Literal("Weakness")))
    graph.add((CG.Reference, RDFS.label, Literal("Reference")))

    # Define Object Properties (relationships between entities)
    # These link instances of classes together, e.g., a vulnerability affects a software product
    object_properties = [
        CG.affects,        # Links a Vulnerability to a SoftwareProduct it impacts
        CG.hasWeakness,    # Links a Vulnerability to a Weakness (CWE) it exhibits
        CG.hasReference,   # Links a Vulnerability to an external Reference (e.g., advisory)
    ]

    for prop in object_properties:
        graph.add((prop, RDF.type, OWL.ObjectProperty))

    # Define Datatype Properties (attributes with literal values)
    # These attach data values to entities, e.g., severity score of a vulnerability
    data_properties = [
        CG.hasSeverity,      # Severity level (e.g., CRITICAL, HIGH) of a Vulnerability
        CG.hasScore,         # Numerical CVSS score of a Vulnerability
        CG.description,      # Text description of a Vulnerability
        CG.publishedAt,      # Publication date of a Vulnerability
        CG.lastModifiedAt,   # Last modification date of a Vulnerability
    ]

    for prop in data_properties:
        graph.add((prop, RDF.type, OWL.DatatypeProperty))

    # Define Domains and Ranges for properties to constrain their usage
    # Domain: The class the property applies to (subject)
    # Range: The class or datatype the property points to (object)
    graph.add((CG.affects, RDFS.domain, CG.Vulnerability))          # affects relates Vulnerabilities
    graph.add((CG.affects, RDFS.range, CG.SoftwareProduct))          # to SoftwareProducts

    graph.add((CG.hasWeakness, RDFS.domain, CG.Vulnerability))       # hasWeakness relates Vulnerabilities
    graph.add((CG.hasWeakness, RDFS.range, CG.Weakness))             # to Weaknesses

    graph.add((CG.hasReference, RDFS.domain, CG.Vulnerability))      # hasReference relates Vulnerabilities
    graph.add((CG.hasReference, RDFS.range, CG.Reference))           # to References

    # Datatype properties apply to Vulnerabilities and have literal (string/date) values
    graph.add((CG.hasSeverity, RDFS.domain, CG.Vulnerability))
    graph.add((CG.hasScore, RDFS.domain, CG.Vulnerability))
    graph.add((CG.description, RDFS.domain, CG.Vulnerability))