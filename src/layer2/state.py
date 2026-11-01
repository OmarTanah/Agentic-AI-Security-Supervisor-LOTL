from typing import List, TypedDict


class AgentState(TypedDict):
    event: dict
    malicious_hypothesis: str
    benign_hypothesis: str
    evidence: List[str]
    confidence: float
    proposed_action: str
    iteration: int
    max_iterations: int


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
    }