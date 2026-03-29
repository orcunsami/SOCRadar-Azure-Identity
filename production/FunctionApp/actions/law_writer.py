"""
Log Analytics Workspace (LAW) writer via HTTP Data Collector API.
Writes Identity Intelligence records to SOCRadar_Identity_CL custom table.
Password policy: if EnableLogPlaintextPassword=false (default), plaintext is stripped.
"""

import json
import time
import hmac
import base64
import hashlib
import logging
import requests
from datetime import datetime, timezone

logger = logging.getLogger("socradar.identity.law")

LAW_URL = "https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01"

TABLE_MAP = {
    "identity": "SOCRadar_Identity_CL",
}
AUDIT_TABLE = "SOCRadar_Identity_Audit_CL"

BATCH_SIZE = 100


def _build_signature(workspace_id: str, workspace_key: str, date: str, content_length: int) -> str:
    string_to_hash = f"POST\n{content_length}\napplication/json\nx-ms-date:{date}\n/api/logs"
    bytes_to_hash = string_to_hash.encode("utf-8")
    decoded_key = base64.b64decode(workspace_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()
    ).decode("utf-8")
    return f"SharedKey {workspace_id}:{encoded_hash}"


def _post(workspace_id: str, workspace_key: str, log_type: str, records: list) -> bool:
    body = json.dumps(records)
    content_length = len(body.encode("utf-8"))
    rfc1123_date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    signature = _build_signature(workspace_id, workspace_key, rfc1123_date, content_length)

    headers = {
        "Content-Type":  "application/json",
        "Authorization": signature,
        "Log-Type":      log_type,
        "x-ms-date":     rfc1123_date,
    }
    url = LAW_URL.format(workspace_id=workspace_id)
    try:
        resp = requests.post(url, data=body, headers=headers, timeout=30)
        if resp.status_code in (200, 201, 202):
            logger.info("[LAW] %s: %d records written", log_type, len(records))
            return True
        logger.error("[LAW] %s: HTTP %d — %s", log_type, resp.status_code, resp.text[:200])
        return False
    except requests.RequestException as e:
        logger.error("[LAW] %s: request error — %s", log_type, e)
        return False


def _clean_record(rec: dict, enable_log_plaintext: bool) -> dict:
    """Remove internal-only fields and enforce password policy."""
    out = {}
    skip_keys = {"_checkpoint_update", "sanitized", "entra_user_id"}
    for k, v in rec.items():
        if k in skip_keys:
            continue
        if k == "password" and not enable_log_plaintext:
            continue
        out[k] = v
    return out


def write_records(conf: dict, source_name: str, records: list):
    """Write source records to appropriate LAW table in batches."""
    log_type = TABLE_MAP.get(source_name, f"SOCRadar_{source_name.upper()}_CL")
    if log_type.endswith("_CL"):
        log_type = log_type[:-3]

    workspace_id = conf["workspace_id"]
    workspace_key = conf["workspace_key"]
    enable_log_plaintext = conf.get("enable_log_plaintext_password", False)

    cleaned = [_clean_record(r, enable_log_plaintext) for r in records]

    for i in range(0, len(cleaned), BATCH_SIZE):
        batch = cleaned[i:i + BATCH_SIZE]
        _post(workspace_id, workspace_key, log_type, batch)
        if i + BATCH_SIZE < len(cleaned):
            time.sleep(0.5)


def write_audit(conf: dict, audit_results: list):
    """Write audit summary records to SOCRadar_Identity_Audit_CL table."""
    workspace_id = conf["workspace_id"]
    workspace_key = conf["workspace_key"]
    ts = datetime.now(timezone.utc).isoformat()

    records = []
    for r in audit_results:
        records.append({
            "source":           r.get("source", ""),
            "total_records":    r.get("total", 0),
            "employee_records": r.get("employees", 0),
            "found_count":      r.get("found", 0),
            "not_found_count":  r.get("not_found", 0),
            "actions_taken":    r.get("actions", 0),
            "error_count":      r.get("errors", 0),
            "duration_sec":     r.get("duration", 0),
            "timestamp":        ts,
        })

    _post(workspace_id, workspace_key, "SOCRadar_Identity_Audit", records)
