from src.layer2.tools.gtfobins import check_gtfobins


def test_find_is_gtfobin() -> None:
    result = check_gtfobins("find")

    assert result["is_gtfobin"] is True
    assert result["risk"] == "high"


def test_full_path_strips_binary_name() -> None:
    result = check_gtfobins("/usr/bin/find")

    assert result["is_gtfobin"] is True


def test_vim_is_gtfobin() -> None:
    result = check_gtfobins("vim")

    assert result["is_gtfobin"] is True


def test_ls_is_not_gtfobin() -> None:
    result = check_gtfobins("ls")

    assert result == {"is_gtfobin": False, "functions": [], "risk": "none"}


def test_nonexistent_binary_is_not_gtfobin() -> None:
    result = check_gtfobins("nonexistent_binary_xyz")

    assert result["is_gtfobin"] is False
