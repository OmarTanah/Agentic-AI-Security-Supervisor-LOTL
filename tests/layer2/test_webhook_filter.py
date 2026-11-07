from src.layer1.store import Store
from src.layer1.webhook import create_app


def test_auditd_benign_command_is_ignored_before_dispatch(tmp_path) -> None:
	dispatched = []
	app = create_app(Store(str(tmp_path / "audit.db")), dispatched.append)

	response = app.test_client().post(
		"/wazuh/event",
		json={"agent": {"name": "host"}, "data": {"audit": {"execve": {"a0": "ls"}}}},
	)

	assert response.status_code == 200
	assert response.get_json() == {"status": "ignored", "reason": "benign_auditd_command"}
	assert dispatched == []


def test_auditd_interesting_command_is_dispatched(tmp_path) -> None:
	dispatched = []
	app = create_app(Store(str(tmp_path / "audit.db")), dispatched.append)

	response = app.test_client().post(
		"/wazuh/event",
		json={"agent": {"name": "host"}, "data": {"audit": {"execve": {"a0": "find"}}}},
	)

	assert response.status_code == 202
	assert response.get_json()["status"] == "accepted"
	assert len(dispatched) == 1