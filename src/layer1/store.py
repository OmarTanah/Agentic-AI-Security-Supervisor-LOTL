"""SQLite audit DB (Layer 1 part) + 60-second de-duplication."""
import json
import sqlite3
import time

DEDUP_WINDOW_S = 60

SCHEMA = """
CREATE TABLE IF NOT EXISTS events(
  event_id TEXT PRIMARY KEY, ts REAL, host TEXT, user TEXT, source TEXT,
  severity TEXT, command_raw TEXT, command_clean TEXT, payload TEXT);
CREATE INDEX IF NOT EXISTS idx_events_host_user ON events(host, user, ts);
CREATE TABLE IF NOT EXISTS dedup(key TEXT PRIMARY KEY, last_seen REAL, count INTEGER);
"""


class Store:
    def __init__(self, path="data/audit.db"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.executescript(SCHEMA)

    def is_duplicate(self, key: str, now: float | None = None) -> bool:
        """True if key was seen < 60s ago. Updates the counter either way."""
        now = now if now is not None else time.time()
        row = self.db.execute("SELECT last_seen, count FROM dedup WHERE key=?", (key,)).fetchone()
        dup = bool(row and now - row[0] < DEDUP_WINDOW_S)
        if row:
            self.db.execute("UPDATE dedup SET last_seen=?, count=? WHERE key=?",
                            (now if not dup else row[0], row[1] + 1, key))
        else:
            self.db.execute("INSERT INTO dedup VALUES(?,?,1)", (key, now))
        self.db.commit()
        return dup

    def save_event(self, ev: dict, now: float | None = None):
        self.db.execute("INSERT OR REPLACE INTO events VALUES(?,?,?,?,?,?,?,?,?)",
                        (ev["event_id"], now or time.time(), ev["host"], ev["user"], ev["source"],
                         ev["severity"], ev["command_raw"], ev["command_clean"], json.dumps(ev)))
        self.db.commit()

    def query_recent_events(self, host: str, user: str | None = None, limit: int = 20):
        q, args = "SELECT payload FROM events WHERE host=?", [host]
        if user:
            q += " AND user=?"; args.append(user)
        q += " ORDER BY ts DESC LIMIT ?"; args.append(limit)
        return [json.loads(r[0]) for r in self.db.execute(q, args)]
