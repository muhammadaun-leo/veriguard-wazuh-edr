#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[1/5] Preparing dropzone and quarantine vault..."
sudo mkdir -p /tmp/monitored_dropzone /var/ossec/quarantine /var/ossec/etc/rules
sudo chmod 777 /tmp/monitored_dropzone
sudo chown root:wazuh /var/ossec/quarantine
sudo chmod 750 /var/ossec/quarantine

echo "[2/5] Installing configs, rules, and Python modules..."
sudo cp "$REPO_DIR/config/vt_config.env" /var/ossec/etc/vt_config.env
sudo chown root:wazuh /var/ossec/etc/vt_config.env
sudo chmod 640 /var/ossec/etc/vt_config.env

sudo cp "$REPO_DIR/rules/custom_malware.yar" /var/ossec/etc/rules/custom_malware.yar
sudo cp "$REPO_DIR/config/local_decoder.xml" /var/ossec/etc/decoders/local_decoder.xml
sudo cp "$REPO_DIR/config/local_rules.xml" /var/ossec/etc/rules/local_rules.xml

sudo cp "$REPO_DIR/scripts/audit_ledger.py" /var/ossec/active-response/bin/audit_ledger.py
sudo cp "$REPO_DIR/scripts/active_response_engine.py" /var/ossec/active-response/bin/active_response_engine.py
sudo cp "$REPO_DIR/scripts/ar_wrapper.sh" /var/ossec/active-response/bin/ar_wrapper.sh

sudo chown root:wazuh /var/ossec/active-response/bin/{audit_ledger.py,active_response_engine.py,ar_wrapper.sh}
sudo chmod 750 /var/ossec/active-response/bin/{audit_ledger.py,active_response_engine.py,ar_wrapper.sh}

echo "[3/5] Updating ossec.conf idempotently..."
sudo python3 - << 'PYEOF'
import re
from pathlib import Path

conf_path = Path("/var/ossec/etc/ossec.conf")
text = conf_path.read_text(encoding="utf-8")
text = re.sub(r"\s*<!-- VERIGUARD_BEGIN -->.*?<!-- VERIGUARD_END -->", "", text, flags=re.DOTALL)

block = """
  <!-- VERIGUARD_BEGIN -->
  <syscheck>
    <directories check_all="yes" realtime="yes" report_changes="no">/tmp/monitored_dropzone</directories>
  </syscheck>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>

  <command>
    <name>veriguard-ar</name>
    <executable>ar_wrapper.sh</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>veriguard-ar</command>
    <location>local</location>
    <rules_id>100500,5712,5763</rules_id>
  </active-response>
  <!-- VERIGUARD_END -->
</ossec_config>"""

conf_path.write_text(text.replace("</ossec_config>", block, 1), encoding="utf-8")
PYEOF

echo "[4/5] Validating Wazuh XML configuration..."
sudo /var/ossec/bin/wazuh-analysisd -t

echo "[5/5] Restarting Wazuh Manager..."
sudo service wazuh-manager restart || sudo systemctl restart wazuh-manager
echo "SUCCESS: VeriGuard deployed cleanly."
