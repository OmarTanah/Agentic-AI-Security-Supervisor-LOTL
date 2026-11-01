"""Layer 1 to Layer 2 agent entry point."""
import argparse
import json
import os
from typing import Any

from dotenv import load_dotenv

from .graph import graph
from .state import create_initial_state


def _structured_answer(result: dict[str, Any]) -> dict[str, Any]:
    """Convert the completed graph state into the public agent response."""
    confidence = float(result.get("confidence", 0.5))
    final_answer = result.get("final_answer", "")
    reasoning = str(final_answer or result.get("thought", ""))

    try:
        parsed_answer = json.loads(reasoning)
    except (TypeError, ValueError, json.JSONDecodeError):
        parsed_answer = None
    if isinstance(parsed_answer, dict):
        return {
            "verdict": str(parsed_answer.get("verdict", "investigate")),
            "confidence": float(parsed_answer.get("confidence", confidence)),
            "reasoning": str(parsed_answer.get("reasoning", reasoning)),
        }

    verdict = "malicious" if confidence >= 0.8 else "benign" if confidence <= 0.2 else "investigate"
    return {"verdict": verdict, "confidence": confidence, "reasoning": reasoning}


def run_agent(event: dict) -> dict:
    """Run the Layer 2 investigation for one normalized Layer 1 event."""
    load_dotenv()
    if not os.getenv("GOOGLE_API_KEY"):
        return {
            "verdict": "error",
            "confidence": 0.0,
            "reasoning": "GOOGLE_API_KEY is missing. Set it in the environment or a .env file.",
        }

    try:
        initial_state = create_initial_state(event)
        result = graph.invoke(initial_state)
        return _structured_answer(result)
    except Exception as error:
        return {
            "verdict": "error",
            "confidence": 0.0,
            "reasoning": f"Agent investigation failed: {error}",
        }


def main() -> None:
    """Load an event file and print the agent's structured result."""
    parser = argparse.ArgumentParser(description="Run the LOTL-ARIA Layer 2 agent")
    parser.add_argument("event_file", help="Path to a normalized event JSON file")
    args = parser.parse_args()
    with open(args.event_file, encoding="utf-8") as event_file:
        event = json.load(event_file)
    print(json.dumps(run_agent(event), indent=2))


if __name__ == "__main__":
    main()