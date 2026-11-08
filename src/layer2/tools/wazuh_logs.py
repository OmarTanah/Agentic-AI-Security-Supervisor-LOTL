"""Read-only local Wazuh event history queries for Layer 2 investigations."""
import json
import os

import requests

from src.layer1.store import Store

WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://127.0.0.1:9200").rstrip("/")


def query_wazuh_logs(query: str) -> dict[str, object]:
	"""Return the five newest Wazuh logs matching ``query``.

	The local SQLite audit history is used when the Indexer is unavailable.
	"""
	try:
		response = requests.get(
			f"{WAZUH_INDEXER_URL}/wazuh-alerts-*,wazuh-archives-*/_search",
			json={
				"size": 5,
				"sort": [{"@timestamp": {"order": "desc"}}],
				"query": {"query_string": {"query": query}},
			},
			verify=False,
			timeout=5,
		)
		response.raise_for_status()
		hits = response.json().get("hits", {}).get("hits", [])
		return {"query": query, "matches": [hit.get("_source", hit) for hit in hits[:5]]}
	except (requests.RequestException, ValueError, AttributeError, TypeError):
		return _query_sqlite_logs(query)


def _query_sqlite_logs(query: str) -> dict[str, object]:
	"""Return the five newest local audit events whose command contains ``query``."""
	store = Store()
	escaped_query = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
	rows = store.db.execute(
		"SELECT payload FROM events "
		"WHERE command_clean LIKE ? ESCAPE '\\' "
		"ORDER BY ts DESC LIMIT 5",
		(f"%{escaped_query}%",),
	).fetchall()
	return {
		"query": query,
		"matches": [json.loads(row[0]) for row in rows],
	}