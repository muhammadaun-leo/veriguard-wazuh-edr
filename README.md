# VeriGuard Wazuh EDR

An automated endpoint detection and active response (EDR) pipeline built on **Wazuh SIEM**, integrating **YARA** signature scanning, **VirusTotal API** threat intelligence, and custom **Python** active response scripts on **Ubuntu Linux**.

## Overview

Traditional host-based intrusion detection often stops at alerting, leaving analysts to manually triage suspicious files and isolate threats. **VeriGuard Wazuh EDR** automates the triage-to-containment lifecycle: when Wazuh File Integrity Monitoring (FIM) detects a new or modified file in monitored directories, a custom pipeline evaluates the artifact locally with YARA, verifies its reputation via VirusTotal, and executes automated quarantine actions upon confirmed malicious indicators.

## Detection & Response Architecture

```text
[Endpoint File Event]
        │
        ▼
[Wazuh Agent (FIM / Sysmon)] ──► [Wazuh Manager & Custom Rules]
                                          │
                        ┌─────────────────┴─────────────────┐
                        ▼                                   ▼
             [Local YARA Scan]                 [VirusTotal API Lookup]
                        │                                   │
                        └─────────────────┬─────────────────┘
                                          ▼
                           [Malicious Threshold Triggered?]
                                    │             │
                                   Yes            No
                                    │             │
                                    ▼             ▼
                        [Python Active Response] [Log & Close]
                        (Quarantine + Alerting)
```

## Key Features

- **Real-Time File Integrity Monitoring (FIM):** Monitors critical Linux directories (e.g., `/tmp`, `/var/www`, `/home`) for unauthorized file creation or modification.
- **Automated YARA Analysis:** Scans suspicious binaries and scripts against custom YARA rules to detect known malware families, webshells, and obfuscated payloads.
- **Threat Intelligence Enrichment:** Queries the VirusTotal v3 API using file SHA-256 hashes to correlate local detections with multi-engine vendor verdicts.
- **Active Containment:** Automatically isolates flagged files into a restricted quarantine directory with stripped execution permissions (`chmod 000`) and logs structured JSON telemetry back to Wazuh.

## Repository Structure

```text
veriguard-wazuh-edr/
├── active-response/       # Custom Python scripts for automated quarantine & remediation
├── rules/                 # Custom Wazuh XML detection rules and alert thresholds
├── yara/                  # Custom YARA rulesets for local artifact scanning
├── config/                # Sample ossec.conf snippets for FIM and active-response blocks
└── README.md
```

## Prerequisites

- **OS:** Ubuntu 22.04 / 24.04 LTS (Manager & Agent)
- **SIEM:** Wazuh Manager & Agent (v4.x+)
- **Runtime:** Python 3.10+ (`requests`, `yara-python`)
- **API Access:** VirusTotal API Key

## Setup & Deployment

1. **Install Python dependencies on the endpoint:**
   ```bash
   pip3 install requests yara-python
   ```

2. **Deploy Active Response scripts:**
   Copy the Python response scripts to the Wazuh active-response binary directory and set appropriate ownership and permissions:
   ```bash
   sudo cp active-response/*.py /var/ossec/active-response/bin/
   sudo chown root:wazuh /var/ossec/active-response/bin/*.py
   sudo chmod 750 /var/ossec/active-response/bin/*.py
   ```

3. **Configure YARA rules & custom Wazuh rules:**
   Place your YARA signatures in `/var/ossec/ruleset/yara/` and append the custom XML rules from `rules/` into `/var/ossec/etc/rules/local_rules.xml`.

4. **Enable FIM & Active Response in `ossec.conf`:**
   Configure `<syscheck>` for real-time directory monitoring and link the custom `<command>` and `<active-response>` blocks in `/var/ossec/etc/ossec.conf`, then restart the manager:
   ```bash
   sudo systemctl restart wazuh-manager
   ```

## Validation & Proof of Concept

To verify end-to-end detection and containment:
1. Drop a benign test signature (such as an EICAR test string) into a monitored directory.
2. Confirm that Wazuh triggers a high-severity FIM/YARA alert in `/var/ossec/logs/alerts/alerts.json`.
3. Verify that the file is automatically moved to the quarantine path and stripped of permissions.


## Future Roadmap

- Map custom detection rules directly to **MITRE ATT&CK** technique IDs.
- Integrate **Sysmon for Linux** telemetry to correlate process creation events with file drops.
- Add automated IP blocking via `iptables`/`ufw` for C2 communication indicators.
