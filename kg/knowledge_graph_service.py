from __future__ import annotations

from kg.graph_builder import build_graph


class KnowledgeGraphService:
    def __init__(self, parsed_data: list[dict]):
        self.graph = build_graph(parsed_data)

    def get_vulnerabilities_by_product(self, product_name: str) -> list[str]:
        query = f"""
        PREFIX ex: <http://example.org/cybergraph/>
        SELECT ?cve WHERE {{
            ?cve ex:affects ?product .
            ?product ex:label ?label .
            FILTER(LCASE(STR(?label)) = LCASE("{product_name}"))
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

    def get_vulnerabilities_by_weakness(self, weakness: str) -> list[str]:
        query = f"""
        PREFIX ex: <http://example.org/cybergraph/>
        SELECT ?cve WHERE {{
            ?cve ex:hasWeakness ?w .
            ?w ex:label ?label .
            FILTER(LCASE(STR(?label)) = LCASE("{weakness}"))
        }}
        """
        results = self.graph.query(query)
        return [str(row.cve).split("/")[-1] for row in results]

    def advanced_search(
        self,
        software: str | None = None,
        severity: str | None = None,
        weakness: str | None = None,
    ) -> list[str]:
        """
        Performs a multi-constraint graph-based search by intersecting:
        - software matches
        - severity matches
        - weakness matches
        """

        sets: list[set[str]] = []

        if software:
            sets.append(set(self.get_vulnerabilities_by_product(software)))

        if severity:
            sets.append(set(self.get_vulnerabilities_by_severity(severity)))

        if weakness:
            sets.append(set(self.get_vulnerabilities_by_weakness(weakness)))

        if not sets:
            return []

        result_ids = set.intersection(*sets)
        return sorted(result_ids)