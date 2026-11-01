"""User command baseline queries for Layer 2 investigations."""
import shlex
import time
from pathlib import Path

from src.layer1.store import Store


def _command_binary(command: str) -> str:
	"""Return the first executable-like token from a shell command."""
	try:
		tokens = shlex.split(command)
	except ValueError:
		return ""

	ignored = {"sudo", "env"}
	for token in tokens:
		if token in ignored or token.startswith("-"):
			continue
		return Path(token).name
	return ""


def get_user_baseline(username: str) -> dict:
	"""Count a user's recent commands and executions of their latest binary."""
	store = Store()
	cutoff = time.time() - (30 * 24 * 60 * 60)
	rows = store.db.execute(
		"SELECT command_clean FROM events WHERE user=? AND ts>=? ORDER BY ts DESC",
		(username, cutoff),
	).fetchall()

	commands = [str(row[0] or "") for row in rows]
	requested_binary = _command_binary(commands[0]) if commands else ""
	binary_executions = sum(
		_command_binary(command) == requested_binary
		for command in commands
		if requested_binary
	)
	return {
		"username": username,
		"total_commands": len(commands),
		"binary_executions": binary_executions,
		"is_anomaly": binary_executions == 0,
	}