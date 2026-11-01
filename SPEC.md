# LOTL-ARIA: Project Specification

## What is it?
An Agentic LLM framework that investigates Linux Living-off-the-Land (LOTL) attacks.
It receives normalized events from Layer 1 (Wazuh), investigates them using a ReAct agent,
and produces a structured verdict with a confidence score.

## Layer 1 (DONE - Do not touch)
- Receives events from Wazuh via Flask webhook.
- De-obfuscates commands (Base64, Hex, ANSI-C).
- Computes heuristic severity (low/medium/high/critical).
- Saves to SQLite (`data/audit.db`).

## Layer 2 (CURRENT TASK)
- **Goal:** Build the ReAct Agent Core using LangGraph.
- **Input:** A `NormalizedEvent` dict (from Layer 1).
- **Output:** A `FinalAnswer` dict with VERDICT, CONFIDENCE, PRIORITY, ACTION, MITRE, REASONING.
- **Loop:** THOUGHT → ACTION → OBSERVATION → UPDATE CONFIDENCE → (repeat until confidence ≥ 0.8 or max 10 iterations).
- **Tools (Read-Only):** `check_gtfobins`, `get_user_baseline`, `get_process_tree`, `query_recent_events`.
- **Safety:** The Agent CANNOT execute actions. It only proposes them. The Safety Gate (Layer 3) handles execution.

## Data Models
```python
class AgentState(TypedDict):
    event: dict
    malicious_hypothesis: str
    benign_hypothesis: str
    evidence: List[str]
    confidence: float
    proposed_action: str
    iteration: int
    max_iterations: int