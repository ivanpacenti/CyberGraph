from rdflib import Graph
from kg.graph_builder import build_graph


class KnowledgeGraphService:
    def __init__(self, parsed_data: list[dict]):
        self.graph: Graph = build_graph(parsed_data)

    def get_vulnerabilities_by_product(self, product_name: str) -> list[str]:
        query = f"""
        PREFIX ex: <http://example.org/cybergraph/>
        SELECT ?cve WHERE {{
            ?cve ex:affects ?product .
            ?product ex:label "{product_name}" .
        }}
        """

        results = self.graph.query(query)
        return [str(row.cve).split("/")[-1] for row in results]

    def get_vulnerabilities_by_severity(self, severity: str) -> list[str]:
        query = f"""
        PREFIX ex: <http://example.org/cybergraph/>
        SELECT ?cve WHERE {{
            ?cve ex:hasSeverity "{severity}" .
        }}
        """
        results = self.graph.query(query)
        return [str(row.cve).split("/")[-1] for row in results]