"""Read-only process parent lookups for Layer 2 investigations."""

from __future__ import annotations

import shlex

import psutil


_WEB_SERVERS = {"apache2", "httpd", "nginx"}


def _matches_command(process: psutil.Process, command: str) -> bool:
	try:
		cmdline = process.cmdline()
	except (psutil.Error, OSError):
		return False
	if not cmdline:
		return False
	try:
		requested = shlex.split(command)
	except ValueError:
		requested = command.split()
	return bool(requested) and any(token in cmdline for token in requested)


def get_process_tree(command: str, pid: int | None = None) -> dict[str, object]:
	"""Return the actual parent process for an event PID or matching command."""
	process = None
	if pid is not None:
		try:
			process = psutil.Process(pid)
		except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
			process = None

	if process is None:
		matches = [candidate for candidate in psutil.process_iter() if _matches_command(candidate, command)]
		if matches:
			process = max(matches, key=lambda candidate: candidate.create_time())

	parent_name = ""
	if process is not None:
		try:
			parent = process.parent()
			parent_name = parent.name() if parent is not None else ""
		except (psutil.Error, OSError):
			parent_name = ""

	return {
		"parent_process": parent_name,
		"is_suspicious_parent": parent_name.lower() in _WEB_SERVERS,
	}
