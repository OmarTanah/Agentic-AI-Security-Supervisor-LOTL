"""Flask webhook: Wazuh Manager -> LOTL-ARIA (Layer 1 entry point)."""
import hmac
import logging
import os

from flask import Flask, jsonify, request

from .normalizer import normalize
from .store import Store

log = logging.getLogger("lotl_aria.layer1")
SHARED_SECRET = ""


def create_app(store: Store | None = None, dispatch=None) -> Flask:
    """`dispatch(event)` is the hand-off to Layer 2 (the ReAct agent)."""
    app = Flask(__name__)
    store = store or Store()
    dispatch = dispatch or (lambda ev: log.info("EVENT -> agent queue: %s", ev["event_id"]))

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
            elif store.is_duplicate(ev["dedup_key"]):
                results.append({"status": "dropped", "reason": "duplicate<60s"})
            else:
                store.save_event(ev)
                dispatch(ev)
                results.append({"status": "accepted", "event_id": ev["event_id"], "severity": ev["severity"]})
        return jsonify(results[0] if not isinstance(payload, list) else results), 202

    @app.get("/health")
    def health():
        return jsonify(status="ok")

    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    create_app().run(host="0.0.0.0", port=5000)
