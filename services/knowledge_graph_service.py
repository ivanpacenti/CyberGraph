from __future__ import annotations

from rdflib import Graph

from kg.graph_builder import build_graph


class KnowledgeGraphService:
    """
    service layer for querying the rdf knowledge graph using sparql.
    """

    def __init__(self, nvd_data: list[dict], cwe_data: dict | None = None):
        # build the rdf graph starting from normalized nvd/cwe data
        self.graph: Graph = build_graph(nvd_data, cwe_data)

    def get_vulnerabilities_by_product(self, product_name: str) -> list[str]:
        # retrieve vulnerabilities affecting a specific software product
        # the search is case insensitive and based on the product label

        query = f"""
        PREFIX cg: <http://example.org/cybergraph/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?cveId WHERE {{
            ?cve a cg:Vulnerability ;
                 cg:cveId ?cveId ;
                 cg:affects ?product .

            ?product rdfs:label ?label .

            FILTER(CONTAINS(LCASE(STR(?label)), LCASE("{product_name}")))
        }}
        """
        return self._extract_cve_ids(query)

    def get_vulnerabilities_by_vendor(self, vendor_name: str) -> list[str]:
        # retrieve vulnerabilities by software vendor
        # this traverses the graph:
        # vulnerability -> product -> vendor

        query = f"""
        PREFIX cg: <http://example.org/cybergraph/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?cveId WHERE {{
            ?cve a cg:Vulnerability ;
                 cg:cveId ?cveId ;
                 cg:affects ?product .

            ?product cg:hasVendor ?vendor .
            ?vendor rdfs:label ?label .

            FILTER(CONTAINS(LCASE(STR(?label)), LCASE("{vendor_name}")))
        }}
        """
        return self._extract_cve_ids(query)

    def get_vulnerabilities_by_severity(self, severity: str) -> list[str]:
        # retrieve vulnerabilities having a given severity level
        # severity is modeled as a graph entity instead of a plain string

        query = f"""
        PREFIX cg: <http://example.org/cybergraph/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?cveId WHERE {{
            ?cve a cg:Vulnerability ;
                 cg:cveId ?cveId ;
                 cg:hasSeverityLevel ?severityNode .

            ?severityNode rdfs:label ?label .

            FILTER(LCASE(STR(?label)) = LCASE("{severity}"))
        }}
        """
        return self._extract_cve_ids(query)

    def get_vulnerabilities_by_weakness(self, weakness: str) -> list[str]:
        """
        retrieve cves by cwe id or semantic weakness label.

        examples:
        - "cwe-190"
        - "integer overflow"
        - "sql injection"
        """

        query = f"""
        PREFIX cg: <http://example.org/cybergraph/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?cveId WHERE {{
            ?cve a cg:Vulnerability ;
                 cg:cveId ?cveId ;
                 cg:hasWeakness ?weakness .

            ?weakness rdfs:label ?label .

            FILTER(CONTAINS(LCASE(STR(?label)), LCASE("{weakness}")))
        }}
        """
        return self._extract_cve_ids(query)

    def advanced_search(
        self,
        software: str | None = None,
        vendor: str | None = None,
        severity: str | None = None,
        weakness: str | None = None,
    ) -> list[str]:
        """
        multi-constraint graph search.

        this combines multiple graph queries together by using
        set intersection between the different result sets.

        example:
        - software = apache
        - severity = critical
        - weakness = sql injection
        """

        result_sets: list[set[str]] = []

        if software:
            result_sets.append(set(self.get_vulnerabilities_by_product(software)))

        if vendor:
            result_sets.append(set(self.get_vulnerabilities_by_vendor(vendor)))

        if severity:
            result_sets.append(set(self.get_vulnerabilities_by_severity(severity)))

        if weakness:
            result_sets.append(set(self.get_vulnerabilities_by_weakness(weakness)))

        # if no filter is provided, return empty result
        if not result_sets:
            return []

        # intersection keeps only vulnerabilities matching all constraints
        return sorted(set.intersection(*result_sets))

    def _extract_cve_ids(self, query: str) -> list[str]:
        # execute sparql query on the rdf graph
        results = self.graph.query(query)

        # extract the original cve id stored in the graph
        return [
            str(row.cveId)
            for row in results
        ]