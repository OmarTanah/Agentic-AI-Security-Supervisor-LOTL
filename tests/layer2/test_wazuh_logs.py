import json
import time

from src.layer1.store import Store
from src.layer2.tools import wazuh_logs


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