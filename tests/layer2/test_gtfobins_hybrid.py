from src.layer2.tools.gtfobins import check_gtfobins


def test_exact_payload_match() -> None:
    result = check_gtfobins("find", r"sudo find . -exec /bin/sh \;")

    assert result["known_payload_match"] == "exact"
    assert result["risk_contribution"] == 0.25


def test_partial_payload_match() -> None:
    result = check_gtfobins("find", r"sudo find /tmp -exec /bin/bash \;")

    assert result["known_payload_match"] == "partial"
    assert result["risk_contribution"] == 0.15


def test_benign_gtfobins_use() -> None:
    result = check_gtfobins("find", 'find /var/log -name "*.log"')

    assert result["known_payload_match"] == "none"
    assert result["risk_contribution"] == 0.0


def test_unknown_binary() -> None:
    result = check_gtfobins("ls", "ls -la")

    assert result == {"binary_in_gtfobins": False, "risk_contribution": 0.0}
