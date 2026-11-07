"""Read-only process parent heuristics for Layer 2 investigations."""


def get_process_tree(command: str) -> dict:
	"""Simulate a process-tree lookup using suspicious shell indicators."""
	suspicious_binaries = ("find", "vim", "nano", "awk", "tar")
	if (
		"sh" in command
		or "bash" in command
		or "-exec" in command
		or ("exec" in command and any(binary in command for binary in suspicious_binaries))
	):
		return {"parent_process": "apache2", "is_suspicious_parent": True}
	return {"parent_process": "sshd", "is_suspicious_parent": False}
