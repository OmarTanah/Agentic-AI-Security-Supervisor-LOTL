"""User command baseline queries for Layer 2 investigations."""
import time

from src.layer1.store import Store


def get_user_baseline(username: str, binary: str) -> dict:
	"""Count a user's recent executions of the explicitly requested binary."""
	store = Store()
	cutoff = time.time() - (30 * 24 * 60 * 60)
	rows = store.db.execute(
		"SELECT command_clean FROM events WHERE user=? AND ts>=? ORDER BY ts DESC",
		(username, cutoff),
	).fetchall()

	commands = [str(row[0] or "") for row in rows]
	binary_executions = sum(binary in command.split() for command in commands)
	return {
		"username": username,
		"total_commands": len(commands),
		"binary_executions": binary_executions,
		"is_anomaly": binary_executions == 0,
	}