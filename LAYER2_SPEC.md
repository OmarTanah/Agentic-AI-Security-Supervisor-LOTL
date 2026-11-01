# Layer 2: ReAct Agent Core — Implementation Plan

## Phase 2.1: State Machine Skeleton (No LLM yet)
- [ ] Create `src/layer2/state.py` with the `AgentState` TypedDict.
- [ ] Create `src/layer2/graph.py` with an empty LangGraph `StateGraph`.
- [ ] Create `tests/layer2/test_state.py` to verify state initialization.

## Phase 2.2: Investigation Tools (Pure Functions)
- [ ] Create `src/layer2/tools/gtfobins.py` with `check_gtfobins(binary: str) -> dict`.
- [ ] Create `src/layer2/tools/baseline.py` with `get_user_baseline(username: str) -> dict`.
- [ ] Create `src/layer2/tools/recent_events.py` with `query_recent_events(host: str) -> list`.
- [ ] Write Pytest tests for EACH tool using mock data.

## Phase 2.3: The ReAct Loop (LLM Integration)
- [ ] Create `src/layer2/prompts.py` with the System Prompt (dual hypotheses, confidence rules).
- [ ] Connect to Ollama via `langchain_ollama.ChatOllama`.
- [ ] Implement the `thought_node`, `action_node`, `observation_node`, and `evaluate_node`.
- [ ] Enforce `max_iterations = 10` and confidence thresholds (≥0.8 malicious, ≤0.2 benign).

## Phase 2.4: Integration with Layer 1
- [ ] Create `src/layer2/agent.py` with `run_agent(event: dict) -> dict`.
- [ ] Connect the Flask `dispatch` function (Layer 1) to call `run_agent`.
- [ ] Test end-to-end: `sudo find` → Layer 1 → Layer 2 → Final Answer in SQLite.