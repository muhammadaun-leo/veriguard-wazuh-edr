#!/usr/bin/env python3
import hashlib
import hmac
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

LEDGER_FILE = Path("/var/ossec/logs/tamper_evident_ledger.jsonl")
GENESIS_HASH = "0" * 64

def _get_key() -> bytes:
    return os.getenv("AUDIT_HMAC_KEY", "ETH_SSRF_2027_VERIGUARD_INTEGRITY_KEY").encode("utf-8")

def compute_chain_hash(prev_hash: str, canonical_json: str) -> str:
    payload = f"{prev_hash}|{canonical_json}".encode("utf-8")
    return hmac.new(_get_key(), payload, hashlib.sha256).hexdigest()

def append_event(stage: str, verdict: str, action: str, target: str, latency_ms: float) -> str:
    prev_hash = GENESIS_HASH
    seq = 1
    if LEDGER_FILE.exists() and LEDGER_FILE.stat().st_size > 0:
        lines = LEDGER_FILE.read_text(encoding="utf-8").strip().splitlines()
        if lines:
            last = json.loads(lines[-1])
            prev_hash = last["entry_hash"]
            seq = last["seq"] + 1

    record = {
        "seq": seq,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "stage": stage,
        "verdict": verdict,
        "action": action,
        "target": target,
        "latency_ms": round(latency_ms, 2),
        "prev_hash": prev_hash,
    }
    canonical = json.dumps(record, sort_keys=True)
    record["entry_hash"] = compute_chain_hash(prev_hash, canonical)

    with LEDGER_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
    return record["entry_hash"][:16]

def verify_ledger() -> bool:
    if not LEDGER_FILE.exists():
        print("[ERROR] Ledger file not found.")
        return False

    expected_prev = GENESIS_HASH
    lines = LEDGER_FILE.read_text(encoding="utf-8").strip().splitlines()
    for idx, line in enumerate(lines, start=1):
        entry = json.loads(line)
        recorded_hash = entry.pop("entry_hash")
        recomputed = compute_chain_hash(expected_prev, json.dumps(entry, sort_keys=True))
        if entry["prev_hash"] != expected_prev or not hmac.compare_digest(recorded_hash, recomputed):
            print(f"[TAMPER DETECTED] Cryptographic chain broken at record #{idx}!")
            return False
        expected_prev = recorded_hash

    print(f"[VERIFIED] All {len(lines)} containment records cryptographically intact.")
    return True

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--verify":
        sys.exit(0 if verify_ledger() else 1)
