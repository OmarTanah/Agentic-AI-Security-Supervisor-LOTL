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


def test_action_node_extracts_final_answer_fields() -> None:
    state = create_initial_state({"command_clean": "sudo find"})
    state.update(
        {
            "action": "final_answer",
            "thought": "I have gathered enough evidence.",
            "action_input": {
                "verdict": "malicious",
                "confidence": 1.0,
                "reasoning": "The exact payload matches GTFOBins.",
            },
        }
    )

    result = graph_module.action_node(state)

    assert result["verdict"] == "malicious"
    assert result["confidence"] == 1.0
    assert result["reasoning"] == "The exact payload matches GTFOBins."
    assert result["final_answer"] == "The exact payload matches GTFOBins."
    assert result["stopped"] is True