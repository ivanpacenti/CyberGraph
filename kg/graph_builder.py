import re
from urllib.parse import quote

from rdflib import Graph, Namespace, URIRef, Literal
from rdflib.namespace import RDF, XSD

EX = Namespace("http://example.org/cybergraph/")


def safe_uri_fragment(text: str) -> str:
    text = text.strip().lower()
    text = text.replace("_", " ")
    text = re.sub(r"\s+", "-", text)   # spazi -> trattini
    return quote(text, safe="-")

def build_graph(parsed_data: list[dict]) -> Graph:
    graph = Graph()
    graph.bind("ex", EX)

    for cve in parsed_data:
        cve_id = cve.get("id")
        if not cve_id:
            continue

        cve_uri = EX[cve_id]

        severity = cve.get("severity")
        if severity:
            graph.add((cve_uri, EX.hasSeverity, Literal(severity)))

        score = cve.get("score")
        if score is not None:
            graph.add((cve_uri, EX.hasScore, Literal(score, datatype=XSD.float)))

        for product in cve.get("product_names", []):
            product_uri = EX[f"product/{safe_uri_fragment(product)}"]
            graph.add((cve_uri, EX.affects, product_uri))
            graph.add((product_uri, EX.label, Literal(product)))

        for weakness in cve.get("weaknesses", []):
            weakness_uri = EX[f"weakness/{weakness.replace(' ', '_')}"]
            graph.add((cve_uri, EX.hasWeakness, weakness_uri))
            graph.add((weakness_uri, EX.label, Literal(weakness)))

    return graph