from src.layer2 import agent as agent_module


def test_run_agent_returns_structured_answer(monkeypatch) -> None:
    monkeypatch.setenv("GOOGLE_API_KEY", "test-key")
    monkeypatch.setattr(
        agent_module.graph,
        "invoke",
        lambda state: {**state, "confidence": 0.9, "final_answer": "Suspicious sudo usage."},
    )

    result = agent_module.run_agent({"command_clean": "sudo find"})

    assert result == {
        "verdict": "malicious",
        "confidence": 0.9,
        "reasoning": "Suspicious sudo usage.",
    }


def test_run_agent_reports_missing_api_key(monkeypatch) -> None:
    monkeypatch.setattr(agent_module, "load_dotenv", lambda: None)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)

    result = agent_module.run_agent({})

    assert result["verdict"] == "error"
    assert "GOOGLE_API_KEY is missing" in result["reasoning"]