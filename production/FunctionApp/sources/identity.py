"""
Identity Intelligence fetcher.
Uses log_start_date/log_end_date + offset pagination.
Returns masked passwords — ROPC NOT possible with this source.
Requires separate Identity API key (pay-per-use).
"""

import time
import logging
import requests
from datetime import datetime, timedelta, timezone

from utils.logger import get_logger
from utils.sanitize import sanitize_password, build_law_password_fields

logger = get_logger("identity")

BASE_URL = "https://platform.socradar.com/api/identity/intelligence/query"
PAGE_SIZE = 25


def fetch(conf: dict, checkpoint: dict) -> list:
    """
    Fetch Identity Intelligence records for all monitored domains since last checkpoint.

    Checkpoint fields used:
        checkpoint_date : str  — log_start_date for next run (YYYY-MM-DD)
        offset          : int  — not used in multi-domain mode (always 0)

    API params: query=<domain>&query_type=domain&log_start_date=YYYY-MM-DD&log_end_date=YYYY-MM-DD&limit=25&offset=N
    Response:   body["data"]["result"] list, body["data"]["checkpoint"] (latest record date),
                body["data"]["offset"] (next offset, None when no more pages)
    """
    api_key = conf["socradar_identity_api_key"]
    domains = conf.get("monitored_domains", [])
    enable_log_plaintext = conf.get("enable_log_plaintext_password", False)
    initial_lookback_minutes = conf.get("initial_lookback_minutes", 600)

    if not domains:
        logger.warning("[IDENTITY] No domains configured in MONITORED_DOMAINS — skipping")
        return []

    logger.info(f"[IDENTITY] Starting fetch. domains={domains}")

    # Determine log_start_date: checkpoint or initial lookback
    shared_checkpoint_date = checkpoint.get("checkpoint_date", "")
    if not shared_checkpoint_date:
        lookback_dt = datetime.now(timezone.utc) - timedelta(minutes=initial_lookback_minutes)
        shared_checkpoint_date = lookback_dt.strftime("%Y-%m-%d")
        logger.info(f"[IDENTITY] No checkpoint, using initial lookback: {shared_checkpoint_date}")

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    final_checkpoint_date = shared_checkpoint_date

    all_records = []

    for domain in domains:
        domain_records, last_checkpoint_date, _ = _fetch_domain(
            api_key=api_key,
            domain=domain,
            log_start_date=shared_checkpoint_date,
            log_end_date=today,
            offset=0,
            enable_log_plaintext=enable_log_plaintext,
        )
        all_records.extend(domain_records)
        if last_checkpoint_date:
            final_checkpoint_date = last_checkpoint_date

    logger.info(f"[IDENTITY] Fetch complete. domains={len(domains)}, total={len(all_records)}")

    if all_records:
        all_records[-1]["_checkpoint_update"] = {
            "checkpoint_date": final_checkpoint_date,
            "offset": 0,
        }
    elif final_checkpoint_date:
        all_records.append({
            "_checkpoint_update": {
                "checkpoint_date": final_checkpoint_date,
                "offset": 0,
            }
        })

    return all_records


def _fetch_domain(api_key: str, domain: str, log_start_date: str, log_end_date: str, offset: int, enable_log_plaintext: bool) -> tuple:
    """Fetch all pages for a single domain. Returns (records, last_checkpoint_date, last_offset)."""
    headers = {"Api-Key": api_key, "Content-Type": "application/json"}
    new_checkpoint_date = log_start_date
    new_offset = offset
    domain_records = []
    page = 0

    logger.info(f"[IDENTITY] domain={domain} log_start_date={log_start_date!r} log_end_date={log_end_date!r} offset={offset}")

    while True:
        params = {
            "query":          domain,
            "query_type":     "domain",
            "log_start_date": log_start_date,
            "log_end_date":   log_end_date,
            "limit":          PAGE_SIZE,
            "offset":         new_offset,
        }

        try:
            resp = requests.get(BASE_URL, headers=headers, params=params, timeout=30)
        except requests.RequestException as e:
            logger.error(f"[IDENTITY] domain={domain} request failed: {e}")
            break

        if resp.status_code != 200:
            logger.error(f"[IDENTITY] domain={domain} API error {resp.status_code}: {resp.text[:200]}")
            break

        body = resp.json()
        if not body.get("is_success"):
            logger.error(f"[IDENTITY] domain={domain} is_success=false: {body.get('message', 'unknown')}")
            break

        payload = body.get("data", {})
        records = payload.get("result", [])
        next_checkpoint = payload.get("checkpoint")  # date of latest record in this page
        next_offset = payload.get("offset")          # None when no more pages

        if not records:
            logger.info(f"[IDENTITY] domain={domain} no more records")
            break

        page += 1
        for rec in records:
            pw_raw = rec.get("password")
            sanitized = sanitize_password(pw_raw)
            pw_fields = build_law_password_fields(sanitized, enable_log_plaintext)
            del sanitized["_raw"]

            entry = {
                "email":            rec.get("username", ""),  # API field is "username" (email address)
                "url":              rec.get("url", ""),
                "country":          rec.get("country", ""),
                "log_date":         rec.get("log_date", ""),
                "insert_date":      rec.get("insert_date", ""),
                "monitored_domain": domain,
                "source":           "identity",
                "is_employee":      True,
                **pw_fields,
            }
            domain_records.append(entry)

        logger.info(f"[IDENTITY] domain={domain} page={page}: {len(records)} records")

        if next_checkpoint:
            new_checkpoint_date = next_checkpoint
        if next_offset is not None:
            new_offset = next_offset
        else:
            break

        time.sleep(1)

    return domain_records, new_checkpoint_date, new_offset
