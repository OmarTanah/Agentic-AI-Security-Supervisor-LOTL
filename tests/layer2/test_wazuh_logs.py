import json
import time

from src.layer1.store import Store
from src.layer2.tools import wazuh_logs


def test_query_wazuh_logs_uses_indexer_results(monkeypatch) -> None:
	class FakeResponse:
		def raise_for_status(self) -> None:
			return None

		def json(self) -> dict:
			return {"hits": {"hits": [{"_source": {"event_id": 1}}]}}

	def fake_get(url, *, json, verify, timeout):
		assert url.endswith("/wazuh-alerts-*,wazuh-archives-*/_search")
		assert json["size"] == 5
		assert json["query"] == {"query_string": {"query": "find"}}
		assert verify is False
		assert timeout == 5
		return FakeResponse()

	monkeypatch.setattr(wazuh_logs.requests, "get", fake_get)

	result = wazuh_logs.query_wazuh_logs("find")

	assert result == {"query": "find", "matches": [{"event_id": 1}]}


def test_query_wazuh_logs_returns_five_newest_matches(tmp_path, monkeypatch) -> None:
	store = Store(str(tmp_path / "audit.db"))
	now = time.time()
	for index in range(6):
		command = f"sudo find /tmp/{index}"
		store.db.execute(
			"INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
			(index, now - index, "host", "user", "auditd", "high", command, command, json.dumps({"event_id": index})),
		)
	store.db.commit()
	monkeypatch.setattr(wazuh_logs, "Store", lambda: store)

	result = wazuh_logs.query_wazuh_logs("find")

	assert result["query"] == "find"
	assert [match["event_id"] for match in result["matches"]] == [0, 1, 2, 3, 4]