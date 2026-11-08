import time

from src.layer1.store import Store
from src.layer2.tools import baseline


def test_get_user_baseline_counts_latest_binary_in_last_30_days(tmp_path, monkeypatch) -> None:
	store = Store(str(tmp_path / "audit.db"))
	now = time.time()
	rows = [
		("newest", now, "sudo find ."),
		("repeat", now - 1, "find /tmp"),
		("other", now - 2, "ls /tmp"),
		("old", now - (31 * 24 * 60 * 60), "find /old"),
	]
	for event_id, timestamp, command in rows:
		store.db.execute(
			"INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?)",
			(event_id, timestamp, "host", "www-data", "source", "high", command, command, "{}"),
		)
	store.db.commit()
	monkeypatch.setattr(baseline, "Store", lambda: store)

	assert baseline.get_user_baseline("www-data", "find") == {
		"username": "www-data",
		"total_commands": 3,
		"binary_executions": 2,
		"is_anomaly": False,
	}


def test_get_user_baseline_marks_unknown_user_as_anomaly(tmp_path, monkeypatch) -> None:
	store = Store(str(tmp_path / "audit.db"))
	monkeypatch.setattr(baseline, "Store", lambda: store)

	assert baseline.get_user_baseline("unknown", "find") == {
		"username": "unknown",
		"total_commands": 0,
		"binary_executions": 0,
		"is_anomaly": True,
	}