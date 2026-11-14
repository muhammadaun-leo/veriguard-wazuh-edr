#!/usr/bin/env bash
set -euo pipefail
source /var/ossec/etc/vt_config.env
export VT_API_KEY VT_MALICIOUS_THRESHOLD AUDIT_HMAC_KEY SAFE_WHITELIST_IPS
exec /usr/bin/python3 /var/ossec/active-response/bin/active_response_engine.py
