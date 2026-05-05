from __future__ import annotations

from rdflib import Graph

from kg.graph_builder import build_graph


class KnowledgeGraphService:
    """
    Service layer for querying the RDF knowledge graph using SPARQL.
    """

    def __init__(self, nvd_data: list[dict], cwe_data: dict | None = None):
        self.graph: Graph = build_graph(nvd_data, cwe_data)

    def get_vulnerabilities_by_product(self, product_name: str) -> list[str]:
        query = f"""
        PREFIX cg: <http://example.org/cybergraph/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?cve WHERE {{
            ?cve a cg:Vulnerability ;
                 cg:affects ?product .

            ?product rdfs:label ?label .

            FILTER(CONTAINS(LCASE(STR(?label)), LCASE("{product_name}")))
        }}
        """
        return self._extract_cve_ids(query)

    def get_vulnerabilities_by_severity(self, severity: str) -> list[str]:
        query = f"""
        PREFIX cg: <http://example.org/cybergraph/>

        SELECT ?cve WHERE {{
            ?cve a cg:Vulnerability ;
                 cg:hasSeverity "{severity}" .
        }}
        """
        return self._extract_cve_ids(query)

    def get_vulnerabilities_by_weakness(self, weakness: str) -> list[str]:
        """
        Retrieve CVEs by CWE ID or CWE semantic label.

        Works with:
        - "CWE-190"
        - "Integer Overflow"
        - "Integer Overflow or Wraparound"
        """
        query = f"""
        PREFIX cg: <http://example.org/cybergraph/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?cve WHERE {{
            ?cve a cg:Vulnerability ;
                 cg:hasWeakness ?weakness .
            ?weakness rdfs:label ?label .
            FILTER(CONTAINS(LCASE(STR(?label)), LCASE("{weakness}")))
        }}
        """
        return self._extract_cve_ids(query)

    def advanced_search(
        self,
        software: str | None = None,
        severity: str | None = None,
        weakness: str | None = None,
    ) -> list[str]:
        """
        Multi-constraint graph query.

        It combines multiple graph-based searches by intersection:
        - affected software
        - severity
        - weakness / CWE
        """
        result_sets: list[set[str]] = []

        if software:
            result_sets.append(set(self.get_vulnerabilities_by_product(software)))

        if severity:
            result_sets.append(set(self.get_vulnerabilities_by_severity(severity)))

        if weakness:
            result_sets.append(set(self.get_vulnerabilities_by_weakness(weakness)))

        if not result_sets:
            return []

        return sorted(set.intersection(*result_sets))

    def _extract_cve_ids(self, query: str) -> list[str]:
        results = self.graph.query(query)

        return [
            str(row.cve).split("/")[-1]
            for row in results
        ]