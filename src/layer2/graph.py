import json
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import END, START, StateGraph

from .llm import get_llm
from .prompts import SYSTEM_PROMPT
from .state import AgentState
from .tools.baseline import get_user_baseline
from .tools.gtfobins import check_gtfobins
from .tools.process_tree import get_process_tree

llm: Any = None


def _event_value(event: dict, *keys: str) -> Any:
	for key in keys:
		if key in event:
			return event[key]
	return None


def _model_text(response: Any) -> str:
	content = getattr(response, "content", response)
	if isinstance(content, list):
		return "".join(
			item.get("text", "") if isinstance(item, dict) else str(item)
			for item in content
		)
	return str(content)


def _extract_json_object(text: str) -> str:
	"""Extract the first valid JSON object from model output."""
	cleaned = text.strip()
	if cleaned.startswith("```"):
		lines = cleaned.splitlines()
		if lines and lines[0].startswith("```"):
			lines = lines[1:]
		if lines and lines[-1].strip() == "```":
			lines = lines[:-1]
		cleaned = "\n".join(lines).strip()

	decoder = json.JSONDecoder()
	for index, character in enumerate(cleaned):
		if character != "{":
			continue
		try:
			_, end = decoder.raw_decode(cleaned[index:])
			return cleaned[index : index + end]
		except json.JSONDecodeError:
			continue
	raise json.JSONDecodeError("No valid JSON object found", cleaned, 0)


def thought_node(state: AgentState) -> dict[str, Any]:
	"""Ask Gemini for the next ReAct thought and action."""
	global llm
	if llm is None:
		llm = get_llm()
	response = llm.invoke(
		[
			SystemMessage(content=SYSTEM_PROMPT),
			HumanMessage(content=json.dumps(dict(state), default=str)),
		]
	)
	raw_text = _model_text(response)
	print(f"RAW LLM OUTPUT: {response}")
	try:
		decision = json.loads(_extract_json_object(raw_text))
		if not isinstance(decision, dict):
			raise TypeError("LLM response must be a JSON object")
		action_input = decision.get("action_input", {})
		if not isinstance(action_input, dict):
			action_input = {}
		action = str(decision.get("action", "final_answer"))
		return {
			"thought": str(decision.get("thought", "")),
			"action": action,
			"action_input": action_input,
			"proposed_action": action,
			"iteration": state["iteration"] + 1,
		}
	except (TypeError, ValueError, json.JSONDecodeError) as error:
		return {
			"thought": f"Unable to parse the model response: {error}",
			"action": "final_answer",
			"action_input": {},
			"proposed_action": "final_answer",
			"final_answer": "Investigation stopped because the model returned invalid JSON.",
			"stopped": True,
			"iteration": state["iteration"] + 1,
		}


def action_node(state: AgentState) -> dict[str, Any]:
	"""Execute one supported read-only investigation tool."""
	action = state["action"]
	if action == "final_answer":
		return {"final_answer": state["thought"], "stopped": True}
	action_input = state["action_input"]
	if action == "check_gtfobins":
		value = action_input.get("binary")
		if value is None:
			value = _event_value(state["event"], "binary", "command_clean", "command") or ""
		result = check_gtfobins(str(value))
		evidence_marker = "gtfobins:true"
		confidence_delta = 0.25 if result.get("is_gtfobin") is True else 0.0
	elif action == "get_user_baseline":
		value = action_input.get("username")
		if value is None:
			value = _event_value(state["event"], "user", "username") or ""
		result = get_user_baseline(str(value))
		evidence_marker = "baseline:anomaly"
		confidence_delta = 0.15 if result.get("is_anomaly") is True else 0.0
	elif action == "get_process_tree":
		value = action_input.get("command")
		if value is None:
			value = _event_value(state["event"], "command_clean", "command") or ""
		result = get_process_tree(str(value))
		evidence_marker = "parent:suspicious"
		confidence_delta = 0.15 if result.get("is_suspicious_parent") is True else 0.0
	else:
		return {
			"observation": {"error": f"Unknown read-only tool: {action}"},
			"evidence": state["evidence"] + [f"unknown_tool:{action}"],
		}
	updates: dict[str, Any] = {"observation": result}
	evidence = list(state["evidence"])
	if confidence_delta and evidence_marker not in evidence:
		updates["confidence"] = min(1.0, state["confidence"] + confidence_delta)
		evidence.append(evidence_marker)

	parent = str(_event_value(state["event"], "parent_process", "parent") or "").lower()
	if any(server in parent for server in ("httpd", "apache", "nginx", "iis", "gunicorn", "uwsgi")) and "parent:web_server" not in evidence:
		updates["confidence"] = min(1.0, updates.get("confidence", state["confidence"]) + 0.15)
		evidence.append("parent:web_server")

	daily = _event_value(state["event"], "runs_daily", "command_runs_daily", "daily")
	if daily is True and "daily:true" not in evidence:
		updates["confidence"] = max(0.0, updates.get("confidence", state["confidence"]) - 0.25)
		evidence.append("daily:true")
	updates["evidence"] = evidence
	return updates


def evaluate_node(state: AgentState) -> dict[str, Any]:
	"""Mark the investigation complete when a stopping condition is met."""
	iteration = state["iteration"]
	confidence = state["confidence"]
	print(f"Iteration {iteration}: Confidence = {confidence}")
	stopped = state["stopped"] or state["confidence"] >= 0.8 or state["confidence"] <= 0.2
	if iteration >= 10 or iteration >= state["max_iterations"]:
		stopped = True
	return {"stopped": stopped}


def route_after_evaluate(state: AgentState) -> str:
	return END if state["stopped"] else "thought"


workflow = StateGraph(AgentState)
workflow.add_node("thought", thought_node)
workflow.add_node("action", action_node)
workflow.add_node("evaluate", evaluate_node)
workflow.add_edge(START, "thought")
workflow.add_edge("thought", "action")
workflow.add_edge("action", "evaluate")
workflow.add_conditional_edges("evaluate", route_after_evaluate, {"thought": "thought", END: END})
graph = workflow.compile()