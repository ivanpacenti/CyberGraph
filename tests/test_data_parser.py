from app.data_parser import extract_nvd_info


def test_extract_nvd_info_parses_basic_nvd_entry():
    raw_item = {
        "cve": {
            "id": "CVE-2019-13126",
            "published": "2019-07-29T17:15:11.467",
            "lastModified": "2026-03-30T14:30:00.877",
            "vulnStatus": "Modified",
            "descriptions": [
                {
                    "lang": "en",
                    "value": "An integer overflow in NATS Server before 2.0.2 allows a remote attacker to crash the server."
                }
            ],
            "metrics": {
                "cvssMetricV31": [
                    {
                        "cvssData": {
                            "baseSeverity": "HIGH",
                            "baseScore": 7.5
                        }
                    }
                ]
            },
            "weaknesses": [
                {
                    "description": [
                        {
                            "lang": "en",
                            "value": "CWE-190"
                        }
                    ]
                }
            ],
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "criteria": "cpe:2.3:a:linuxfoundation:nats-server:*:*:*:*:*:*:*:*"
                                }
                            ]
                        }
                    ]
                }
            ],
            "references": [
                {
                    "url": "https://example.com/advisory"
                }
            ]
        }
    }

    parsed = extract_nvd_info(raw_item)

    assert parsed["id"] == "CVE-2019-13126"
    assert parsed["severity"] == "HIGH"
    assert parsed["score"] == 7.5
    assert parsed["weaknesses"] == ["CWE-190"]
    assert "nats-server" in parsed["product_names"]
    assert parsed["references"] == ["https://example.com/advisory"]