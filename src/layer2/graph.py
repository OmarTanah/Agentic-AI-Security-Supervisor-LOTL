import json
import re
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import END, START, StateGraph

from .llm import get_llm
from .prompts import SYSTEM_PROMPT
from .state import AgentState
from .tools.baseline import get_user_baseline
from .tools.gtfobins import check_gtfobins
from .tools.process_tree import get_process_tree
from .tools.wazuh_logs import query_wazuh_logs

llm: Any = None


def _event_value(event: dict, *keys: str) -> Any:
	for key in keys:
		if key in event:
			return event[key]
	return None


def _model_text(response: Any) -> str:
	content = getattr(response, "content", response)
	if isinstance(content, str) and not content:
		additional_kwargs = getattr(response, "additional_kwargs", {})
		if isinstance(additional_kwargs, dict):
			reasoning_content = additional_kwargs.get("reasoning_content")
			if reasoning_content:
				content = str(reasoning_content)
	if isinstance(content, list):
		if not content:
			return ""
		first_block = content[0]
		if isinstance(first_block, dict):
			return str(first_block.get("text", ""))
		return str(first_block)
	return str(content)


def _extract_json_object(text: str) -> str:
	"""Extract a JSON object from model output, ignoring surrounding text."""
	match = re.search(r"\{.*\}", text, re.DOTALL)
	if match is None:
		raise json.JSONDecodeError("No JSON object found", text, 0)
	return match.group(0)


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
		if action == "final_answer":
			action_input = {
				**action_input,
				"verdict": decision.get("verdict", action_input.get("verdict")),
				"confidence": decision.get("confidence", action_input.get("confidence")),
				"reasoning": decision.get("reasoning", action_input.get("reasoning")),
			}
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
		action_input = state["action_input"]
		verdict = str(action_input.get("verdict", "investigate")).lower()
		if verdict not in ("malicious", "benign", "investigate"):
			verdict = "investigate"
		try:
			confidence = float(action_input.get("confidence", state["confidence"]))
		except (TypeError, ValueError):
			confidence = state["confidence"]
		confidence = min(1.0, max(0.0, confidence))
		reasoning_value = action_input.get("reasoning") or state["thought"]
		reasoning = str(reasoning_value)
		return {
			"verdict": verdict,
			"confidence": confidence,
			"reasoning": reasoning,
			"final_answer": reasoning,
			"stopped": True,
		}
	action_input = state["action_input"]
	if action == "check_gtfobins":
		binary = action_input.get("binary") or _event_value(state["event"], "binary")
		command = action_input.get("command") or _event_value(state["event"], "command_clean", "command") or ""
		if binary is None:
			binary = str(command).split(maxsplit=1)[0] if command else ""
		result = check_gtfobins(str(binary), str(command))
		if not command:
			result = {**check_gtfobins(str(binary)), **result}
		evidence_marker = "gtfobins:true"
		if not command and result.get("binary_in_gtfobins") is True:
			confidence_delta = 0.25
		else:
			confidence_delta = float(result.get("risk_contribution", 0.0))
	elif action == "get_user_baseline":
		value = action_input.get("username")
		if value is None:
			value = _event_value(state["event"], "user", "username") or ""
		binary = action_input.get("binary")
		if binary is None:
			binary = _event_value(state["event"], "binary") or ""
		result = get_user_baseline(str(value), str(binary))
		evidence_marker = "baseline:anomaly"
		confidence_delta = 0.15 if result.get("is_anomaly") is True else 0.0
	elif action == "get_process_tree":
		value = action_input.get("command")
		if value is None:
			value = _event_value(state["event"], "command_clean", "command") or ""
		pid = action_input.get("pid")
		if pid is None:
			pid = _event_value(state["event"], "pid", "process_id")
		result = get_process_tree(str(value), int(pid) if pid is not None else None)
		evidence_marker = "parent:suspicious"
		confidence_delta = 0.15 if result.get("is_suspicious_parent") is True else 0.0
	elif action == "query_wazuh_logs":
		value = action_input.get("query")
		if value is None:
			value = _event_value(state["event"], "command_clean", "command") or ""
		result = query_wazuh_logs(str(value))
		evidence_marker = "wazuh_logs:match"
		confidence_delta = 0.0
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