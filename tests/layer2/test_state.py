from src.layer2.state import create_initial_state


def test_default_state_initializes_confidence_and_iteration() -> None:
    state = create_initial_state()

    assert state["confidence"] == 0.5
    assert state["iteration"] == 0