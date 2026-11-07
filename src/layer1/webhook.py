"""Flask webhook: Wazuh Manager -> LOTL-ARIA (Layer 1 entry point)."""
import hmac
import logging
import os
import threading

from flask import Flask, jsonify, request

from src.layer2.agent import run_agent

from .normalizer import normalize
from .store import Store

log = logging.getLogger("lotl_aria.layer1")
SHARED_SECRET = ""
AUDITD_INTERESTING_KEYWORDS = (
    "sudo", "find", "bash", "sh", "nc", "socat", "python", "perl", "vim", "nano", "awk", "tar"
)


def run_agent_task(ev: dict) -> None:
    """Run the Layer 2 agent in the background and print its result."""
    try:
        result = run_agent(ev)
        print(f"AGENT VERDICT: {result['verdict']} (Confidence: {result['confidence']})")
        print(f"AGENT REASONING: {result['reasoning']}")
    except Exception:
        log.exception("Layer 2 agent failed for event %s", ev.get("event_id"))


def create_app(store: Store | None = None, dispatch=None) -> Flask:
    """`dispatch(event)` is the hand-off to Layer 2 (the ReAct agent)."""
    app = Flask(__name__)
    store = store or Store()

    def default_dispatch(event: dict) -> None:
        threading.Thread(target=run_agent_task, args=(event,), daemon=True).start()

    dispatch = dispatch or default_dispatch

    @app.post("/wazuh/event")
    def ingest():
        # Accepts one decoded Wazuh event (dict) or a batch (list of dicts).
       # token = request.headers.get("X-ARIA-Token", "")
       # if not hmac.compare_digest(token, SHARED_SECRET):
        #    return jsonify(error="unauthorized"), 401 
        payload = request.get_json(silent=True)
        batch = payload if isinstance(payload, list) else [payload]
        if not batch or not all(isinstance(e, dict) for e in batch):
            return jsonify(error="invalid json"), 400
        results = []
        for raw in batch:
            ev = normalize(raw)
            if ev is None:
                results.append({"status": "ignored", "reason": "no command field"})
            elif ev["source"] == "auditd" and not any(
                keyword in ev["command_clean"].lower() for keyword in AUDITD_INTERESTING_KEYWORDS
            ):
                results.append({"status": "ignored", "reason": "benign_auditd_command"})
            elif store.is_duplicate(ev["dedup_key"]):
                results.append({"status": "dropped", "reason": "duplicate<60s"})
            else:
                store.save_event(ev)
                dispatch(ev)
                results.append({"status": "accepted", "event_id": ev["event_id"], "severity": ev["severity"]})
        status_code = 200 if results and all(result["status"] == "ignored" for result in results) else 202
        return jsonify(results[0] if not isinstance(payload, list) else results), status_code

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    create_app().run(host="0.0.0.0", port=5000)
