from src.layer2.tools import process_tree


class FakeParent:
	def __init__(self, name: str) -> None:
		self._name = name

	def name(self) -> str:
		return self._name


class FakeProcess:
	def __init__(self, parent_name: str) -> None:
		self._parent = FakeParent(parent_name)

	def parent(self) -> FakeParent:
		return self._parent


def test_pid_lookup_returns_actual_web_server_parent(monkeypatch) -> None:
	monkeypatch.setattr(process_tree.psutil, "Process", lambda pid: FakeProcess("apache2"))

	assert process_tree.get_process_tree("id", pid=123) == {
		"parent_process": "apache2",
		"is_suspicious_parent": True,
	}


def test_missing_pid_without_match_has_no_guessed_parent(monkeypatch) -> None:
	monkeypatch.setattr(process_tree.psutil, "process_iter", lambda: [])

	assert process_tree.get_process_tree("find /tmp") == {
		"parent_process": "",
		"is_suspicious_parent": False,
	}