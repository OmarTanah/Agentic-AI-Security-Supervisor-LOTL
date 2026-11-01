from src.layer2.tools.process_tree import get_process_tree


def test_shell_command_has_suspicious_parent() -> None:
	assert get_process_tree("sudo /bin/sh -c id") == {
		"parent_process": "apache2",
		"is_suspicious_parent": True,
	}


def test_non_shell_command_has_normal_parent() -> None:
	assert get_process_tree("find /tmp") == {
		"parent_process": "sshd",
		"is_suspicious_parent": False,
	}