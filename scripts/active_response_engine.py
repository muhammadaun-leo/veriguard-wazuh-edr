#!/usr/bin/env python3
import hashlib
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
from audit_ledger import append_event

LOG_FILE = Path("/var/ossec/logs/active-responses.log")
METRICS_FILE = Path("/var/ossec/logs/pipeline_metrics.jsonl")
QUARANTINE_DIR = Path("/var/ossec/quarantine")
CACHE_FILE = Path("/var/ossec/etc/vt_cache.json")
YARA_RULES = Path("/var/ossec/etc/rules/custom_malware.yar")

VT_API_KEY = os.getenv("VT_API_KEY", "")
VT_THRESHOLD = int(os.getenv("VT_MALICIOUS_THRESHOLD", "3"))
WHITELIST_NETS = [
    ipaddress.ip_network(cidr.strip(), strict=False)
    for cidr in os.getenv("SAFE_WHITELIST_IPS", "127.0.0.1/32").split(",")
    if cidr.strip()
]

def emit_wazuh_log(stage: str, verdict: str, action: str, target: str, latency_ms: float) -> None:
    short_hash = append_event(stage, verdict, action, target, latency_ms)
    ts = datetime.now(timezone.utc).strftime("%Y %b %d %H:%M:%S")
    safe_target = target.replace(" ", "_")
    line = (
        f"{ts} localhost veriguard-ar: "
        f"stage={stage} verdict={verdict} action={action} "
        f"target={safe_target} latency_ms={latency_ms:.2f} chain_hash={short_hash}\n"
    )
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(line)

def record_metric(payload: dict) -> None:
    with METRICS_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload) + "\n")

def sha256_file(filepath: Path) -> str:
    h = hashlib.sha256()
    with filepath.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()

def run_yara(filepath: Path) -> tuple[bool, str, float]:
    t0 = time.perf_counter()
    try:
        res = subprocess.run(
            ["/usr/bin/yara", "-w", str(YARA_RULES), str(filepath)],
            capture_output=True, text=True, timeout=5, check=False
        )
        elapsed = (time.perf_counter() - t0) * 1000.0
        output = res.stdout.strip()
        if output:
            return True, output.split()[0], elapsed
        return False, "none", elapsed
    except Exception as exc:
        return False, f"error:{exc}", (time.perf_counter() - t0) * 1000.0

def query_virustotal(file_hash: str) -> tuple[int, str, float]:
    t0 = time.perf_counter()
    cache = {}
    if CACHE_FILE.exists():
        try:
            cache = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            cache = {}

    if file_hash in cache:
        return cache[file_hash], "cache_hit", (time.perf_counter() - t0) * 1000.0

    if not VT_API_KEY or VT_API_KEY == "YOUR_VT_API_KEY":
        return 0, "local_only_mode", (time.perf_counter() - t0) * 1000.0

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{file_hash}",
            headers={"x-apikey": VT_API_KEY},
            timeout=5,
        )
        elapsed = (time.perf_counter() - t0) * 1000.0
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            malicious = int(stats.get("malicious", 0))
            cache[file_hash] = malicious
            CACHE_FILE.write_text(json.dumps(cache, indent=2), encoding="utf-8")
            return malicious, "vt_v3_live", elapsed
        return 0, f"vt_status_{resp.status_code}", elapsed
    except Exception:
        return 0, "vt_timeout_fallback", (time.perf_counter() - t0) * 1000.0

def quarantine_artifact(filepath: Path, file_hash: str, reason: str) -> None:
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    vault_file = QUARANTINE_DIR / f"{stamp}_{file_hash[:12]}.quar"
    shutil.move(str(filepath), str(vault_file))
    os.chmod(vault_file, 0o000)
    manifest = {
        "original_path": str(filepath),
        "vault_path": str(vault_file),
        "sha256": file_hash,
        "verdict": reason,
        "timestamp_utc": stamp,
    }
    (QUARANTINE_DIR / f"{stamp}_{file_hash[:12]}.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )

def block_ip(src_ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(src_ip)
        if any(ip_obj in net for net in WHITELIST_NETS):
            return False
    except ValueError:
        return False

    ipt_bin = "/usr/sbin/iptables-legacy" if Path("/usr/sbin/iptables-legacy").exists() else "/usr/sbin/iptables"
    check = subprocess.run([ipt_bin, "-C", "INPUT", "-s", src_ip, "-j", "DROP"], capture_output=True, check=False)
    if check.returncode != 0:
        subprocess.run([ipt_bin, "-I", "INPUT", "-s", src_ip, "-j", "DROP"], check=True)
    return True

def main() -> None:
    t_start = time.perf_counter()
    raw = sys.stdin.readline()
    if not raw:
        return
    msg = json.loads(raw)
    alert = msg.get("parameters", {}).get("alert", {})
    rule_id = str(alert.get("rule", {}).get("id", ""))

    syscheck = alert.get("syscheck", {})
    filepath_str = syscheck.get("path")
    if filepath_str:
        filepath = Path(filepath_str)
        if not filepath.exists() or not filepath.is_file():
            return
        file_hash = syscheck.get("sha256_after") or sha256_file(filepath)
        yara_hit, yara_rule, yara_ms = run_yara(filepath)
        vt_hits, vt_status, vt_ms = (0, "skipped_yara_hit", 0.0)
        if not yara_hit:
            vt_hits, vt_status, vt_ms = query_virustotal(file_hash)

        total_ms = (time.perf_counter() - t_start) * 1000.0
        if yara_hit or vt_hits >= VT_THRESHOLD:
            verdict = f"YARA:{yara_rule}" if yara_hit else f"VT:{vt_hits}_engines"
            quarantine_artifact(filepath, file_hash, verdict)
            emit_wazuh_log("file_containment", verdict, "QUARANTINED", filepath_str, total_ms)
            record_metric({
                "plane": "file", "target": filepath_str, "verdict": verdict,
                "action": "QUARANTINED", "yara_ms": round(yara_ms, 2),
                "vt_ms": round(vt_ms, 2), "total_ms": round(total_ms, 2), "vt_source": vt_status
            })
        else:
            emit_wazuh_log("file_inspection", "CLEAN", "ALLOWED", filepath_str, total_ms)
            record_metric({
                "plane": "file", "target": filepath_str, "verdict": "CLEAN",
                "action": "ALLOWED", "yara_ms": round(yara_ms, 2),
                "vt_ms": round(vt_ms, 2), "total_ms": round(total_ms, 2), "vt_source": vt_status
            })
        return

    src_ip = alert.get("data", {}).get("srcip")
    if src_ip:
        blocked = block_ip(src_ip)
        total_ms = (time.perf_counter() - t_start) * 1000.0
        action = "IP_BLOCKED" if blocked else "WHITELIST_SKIPPED"
        emit_wazuh_log("network_containment", f"RULE_{rule_id}", action, src_ip, total_ms)
        record_metric({
            "plane": "network", "target": src_ip, "verdict": f"RULE_{rule_id}",
            "action": action, "total_ms": round(total_ms, 2)
        })

if __name__ == "__main__":
    main()
