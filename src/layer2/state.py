from typing import Any, TypedDict


class AgentState(TypedDict):
    event: dict
    malicious_hypothesis: str
    benign_hypothesis: str
    evidence: list[str]
    confidence: float
    proposed_action: str
    iteration: int
    max_iterations: int
    thought: str
    action: str
    action_input: dict[str, Any]
    observation: Any
    final_answer: str
    stopped: bool


def create_initial_state(event: dict | None = None) -> AgentState:
    return {
        "event": event or {},
        "malicious_hypothesis": "",
        "benign_hypothesis": "",
        "evidence": [],
        "confidence": 0.5,
        "proposed_action": "",
        "iteration": 0,
        "max_iterations": 10,
        "thought": "",
        "action": "",
        "action_input": {},
        "observation": None,
        "final_answer": "",
        "stopped": False,
    }