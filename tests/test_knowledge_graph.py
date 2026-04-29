from services.knowledge_graph_service import KnowledgeGraphService


def test_advanced_search_combines_product_severity_and_weakness():
    parsed_data = [
        {
            "id": "CVE-2019-13126",
            "published": "2019-07-29T17:15:11.467",
            "last_modified": "2026-03-30T14:30:00.877",
            "status": "Modified",
            "description": "Integer overflow in NATS Server.",
            "severity": "HIGH",
            "score": 7.5,
            "weaknesses": ["CWE-190"],
            "products": ["cpe:2.3:a:linuxfoundation:nats-server:*:*:*:*:*:*:*:*"],
            "product_names": ["linuxfoundation", "linuxfoundation nats-server", "nats-server"],
            "references": ["https://example.com/cve-2019-13126"],
        },
        {
            "id": "CVE-0000-0001",
            "published": None,
            "last_modified": None,
            "status": "Analyzed",
            "description": "Different vulnerability.",
            "severity": "LOW",
            "score": 3.1,
            "weaknesses": ["CWE-79"],
            "products": ["cpe:2.3:a:other:other-product:*:*:*:*:*:*:*:*"],
            "product_names": ["other-product"],
            "references": [],
        },
    ]

    cwe_data = {
        "CWE-190": {
            "id": "CWE-190",
            "name": "Integer Overflow or Wraparound",
            "description": "The product performs a calculation that can produce an integer overflow."
        }
    }

    kg_service = KnowledgeGraphService(parsed_data=parsed_data, cwe_data=cwe_data)

    results = kg_service.advanced_search(
        software="nats-server",
        severity="HIGH",
        weakness="CWE-190",
    )

    assert results == ["CVE-2019-13126"]


def test_weakness_can_be_found_by_cwe_name():
    parsed_data = [
        {
            "id": "CVE-2019-13126",
            "description": "Integer overflow in NATS Server.",
            "severity": "HIGH",
            "score": 7.5,
            "weaknesses": ["CWE-190"],
            "products": [],
            "product_names": ["nats-server"],
            "references": [],
        }
    ]

    cwe_data = {
        "CWE-190": {
            "id": "CWE-190",
            "name": "Integer Overflow or Wraparound",
            "description": "Integer overflow weakness."
        }
    }

    kg_service = KnowledgeGraphService(parsed_data=parsed_data, cwe_data=cwe_data)

    results = kg_service.get_vulnerabilities_by_weakness("Integer Overflow")

    assert results == ["CVE-2019-13126"]