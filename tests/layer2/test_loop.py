import json

from langchain_core.messages import AIMessage

from src.layer2 import graph as graph_module
from src.layer2.graph import graph
from src.layer2.state import create_initial_state


class MockLLM:
    def invoke(self, messages: list[object]) -> AIMessage:
        return AIMessage(
            content=json.dumps(
                {
                    "thought": "Check whether the command is a known living-off-the-land binary.",
                    "action": "check_gtfobins",
                    "action_input": {"binary": "find"},
                }
            )
        )


def test_loop_stops_when_confidence_reaches_threshold(monkeypatch) -> None:
    monkeypatch.setattr(graph_module, "llm", MockLLM())
    state = create_initial_state({"parent_process": "nginx"})

    result = graph.invoke(state)

    assert result["confidence"] == 0.9
    assert result["iteration"] == 1
    assert result["stopped"] is True
    assert result["observation"]["is_gtfobin"] is True