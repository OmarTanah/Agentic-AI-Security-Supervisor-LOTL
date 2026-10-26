#!/usr/bin/env python3
"""Tail Wazuh's decoded-event stream and forward every event to LOTL-ARIA.

Why not <integration>? integratord only forwards ALERTS (events that matched a rule),
so a LOTL command with no matching rule would never reach the agent.

Wazuh Manager setup (/var/ossec/etc/ossec.conf, <global>):
    <logall_json>yes</logall_json>      # writes ALL decoded events to archives.json
then: systemctl restart wazuh-manager
Run this on the Manager (or ship the file):  python3 wazuh_forwarder.py
"""
import json, os, time, urllib.request

ARCHIVES = os.environ.get("WAZUH_ARCHIVES", "/var/ossec/logs/archives/archives.json")
HOOK = os.environ.get("ARIA_URL", "http://127.0.0.1:5000/wazuh/event")
TOKEN = os.environ.get("ARIA_WEBHOOK_TOKEN", "change-me")
KEEP = ("sudo", "auditd", "audit")          # cheap pre-filter; the normalizer does the real check


def post(batch):
    req = urllib.request.Request(HOOK, data=json.dumps(batch).encode(), method="POST",
        headers={"Content-Type": "application/json", "X-ARIA-Token": TOKEN})
    urllib.request.urlopen(req, timeout=10)


def follow(path):
    with open(path) as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                if os.stat(path).st_ino != os.fstat(f.fileno()).st_ino:   # log rotation
                    return
                time.sleep(0.5); continue
            yield line


if __name__ == "__main__":
    while True:
        for line in follow(ARCHIVES):
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            blob = (str(ev.get("decoder", {}).get("name", "")) + str(ev.get("location", ""))).lower()
            if any(k in blob for k in KEEP):
                try:
                    post(ev)
                except Exception as e:
                    print("forward failed:", e)
