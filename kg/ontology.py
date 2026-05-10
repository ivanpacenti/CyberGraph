from rdflib import Graph, Namespace, RDF, RDFS, OWL, XSD, Literal

# custom namespaces used in the cybergraph ontology
CG = Namespace("http://example.org/cybergraph/")
CVE = Namespace("http://example.org/cybergraph/cve/")
PRODUCT = Namespace("http://example.org/cybergraph/product/")
VENDOR = Namespace("http://example.org/cybergraph/vendor/")
CWE = Namespace("http://example.org/cybergraph/cwe/")
REF = Namespace("http://example.org/cybergraph/reference/")
SEVERITY = Namespace("http://example.org/cybergraph/severity/")


def bind_namespaces(graph: Graph) -> None:
    """
    bind namespace prefixes to make the rdf graph easier to read
    and easier to query with sparql.
    """

    graph.bind("cg", CG)
    graph.bind("cve", CVE)
    graph.bind("product", PRODUCT)
    graph.bind("vendor", VENDOR)
    graph.bind("cwe", CWE)
    graph.bind("ref", REF)
    graph.bind("severity", SEVERITY)
    graph.bind("rdf", RDF)
    graph.bind("rdfs", RDFS)
    graph.bind("owl", OWL)
    graph.bind("xsd", XSD)


def add_ontology(graph: Graph) -> None:
    """
    add the cybergraph ontology to the rdf graph.

    the ontology defines the main classes, object properties,
    and datatype properties used to represent vulnerabilities,
    software products, vendors, weaknesses, references, and severity levels.
    """

    bind_namespaces(graph)

    # main entity types in the knowledge graph
    classes = {
        CG.Vulnerability: "Vulnerability",
        CG.SoftwareProduct: "Software Product",
        CG.Vendor: "Vendor",
        CG.Weakness: "Weakness",
        CG.Reference: "Reference",
        CG.SeverityLevel: "Severity Level",
    }

    for cls, label in classes.items():
        graph.add((cls, RDF.type, OWL.Class))
        graph.add((cls, RDFS.label, Literal(label)))

    # object properties connect two graph entities together
    object_properties = {
        CG.affects: (
            "affects",
            CG.Vulnerability,
            CG.SoftwareProduct,
        ),
        CG.hasVendor: (
            "has vendor",
            CG.SoftwareProduct,
            CG.Vendor,
        ),
        CG.hasWeakness: (
            "has weakness",
            CG.Vulnerability,
            CG.Weakness,
        ),
        CG.hasReference: (
            "has reference",
            CG.Vulnerability,
            CG.Reference,
        ),
        CG.hasSeverityLevel: (
            "has severity level",
            CG.Vulnerability,
            CG.SeverityLevel,
        ),
    }

    for prop, (label, domain, range_) in object_properties.items():
        graph.add((prop, RDF.type, OWL.ObjectProperty))
        graph.add((prop, RDFS.label, Literal(label)))

        # domain defines the expected subject class
        graph.add((prop, RDFS.domain, domain))

        # range defines the expected object class
        graph.add((prop, RDFS.range, range_))

    # datatype properties attach literal values to graph entities
    data_properties = {
        CG.cveId: (
            "CVE identifier",
            CG.Vulnerability,
            XSD.string,
        ),
        CG.cweId: (
            "CWE identifier",
            CG.Weakness,
            XSD.string,
        ),
        CG.productName: (
            "product name",
            CG.SoftwareProduct,
            XSD.string,
        ),
        CG.vendorName: (
            "vendor name",
            CG.Vendor,
            XSD.string,
        ),
        CG.referenceUrl: (
            "reference URL",
            CG.Reference,
            XSD.anyURI,
        ),
        CG.hasScore: (
            "CVSS score",
            CG.Vulnerability,
            XSD.decimal,
        ),
        CG.description: (
            "description",
            CG.Vulnerability,
            XSD.string,
        ),
        CG.weaknessDescription: (
            "weakness description",
            CG.Weakness,
            XSD.string,
        ),
        CG.publishedAt: (
            "publication date",
            CG.Vulnerability,
            XSD.dateTime,
        ),
        CG.lastModifiedAt: (
            "last modification date",
            CG.Vulnerability,
            XSD.dateTime,
        ),
    }

    for prop, (label, domain, range_) in data_properties.items():
        graph.add((prop, RDF.type, OWL.DatatypeProperty))
        graph.add((prop, RDFS.label, Literal(label)))

        # domain defines which entity type can use this property
        graph.add((prop, RDFS.domain, domain))

        # range defines the expected literal datatype
        graph.add((prop, RDFS.range, range_))