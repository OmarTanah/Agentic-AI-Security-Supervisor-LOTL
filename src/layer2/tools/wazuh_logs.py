"""Read-only local Wazuh event history queries for Layer 2 investigations."""
import json

from src.layer1.store import Store


def query_wazuh_logs(query: str) -> dict[str, object]:
	"""Return the five newest events whose clean command contains ``query``."""
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