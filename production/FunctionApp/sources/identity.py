"""
Identity Intelligence fetcher.
Uses log_start_date/log_end_date + offset pagination.
Returns masked passwords — ROPC NOT possible with this source.
Requires separate Identity API key (pay-per-use).
"""

import json
import time
import hashlib
import logging
import requests
from datetime import datetime, timedelta, timezone

from utils.logger import get_logger
from utils.sanitize import sanitize_password, build_law_password_fields

logger = get_logger("identity")

BASE_URL = "https://platform.socradar.com/api/identity/intelligence/query"
PAGE_SIZE = 25


# Table property limit is 32K chars; a seen-id is 13 chars in the JSON, so 2000 ids leave room for the rest.
MAX_SEEN_TOTAL = 2000


def _short(record_id: str) -> str:
    return hashlib.sha1(record_id.encode("utf-8")).hexdigest()[:10]


def _day(rec: dict) -> str:
    return max((rec.get("log_date") or "")[:10], (rec.get("insert_date") or "")[:10])


def _load_state(checkpoint: dict) -> dict:
    """Per-domain state {domain: {"date": YYYY-MM-DD, "seen": [short ids on that day]}}."""
    try:
        state = json.loads(checkpoint.get("domain_checkpoints") or "{}")
        return state if isinstance(state, dict) else {}
    except ValueError:
        return {}


def fetch(conf: dict, checkpoint: dict) -> list:
    """
    Fetch Identity Intelligence records for all monitored domains since last checkpoint.

    Checkpoint fields used:
        domain_checkpoints : str — JSON {domain: {"date": YYYY-MM-DD, "seen": [...]}}; each domain
                             starts from its own date. "seen" holds the ids already returned for
                             that day, because log_start_date has day resolution and the same day
                             comes back on the next run.
        checkpoint_date    : str — newest domain date; start date for a domain that has no state
        offset             : int — not used in multi-domain mode (always 0)

    API params: query=<domain>&query_type=domain&log_start_date=YYYY-MM-DD&log_end_date=YYYY-MM-DD&limit=25&offset=N
    Response:   body["data"]["result"] list, body["data"]["checkpoint"] (latest record date),
                body["data"]["offset"] (next offset, None when no more pages)
    """
    api_key = conf["socradar_identity_api_key"]
    domains = conf.get("monitored_domains", [])
    enable_log_plaintext = conf.get("enable_log_plaintext_password", False)
    initial_lookback_minutes = conf.get("initial_lookback_minutes", 600)

    if not domains:
        logger.warning("No domains configured in MONITORED_DOMAINS — skipping")
        return []

    logger.info(f"Starting fetch. domains={domains}")

    # Start date for a domain without state: shared checkpoint or initial lookback
    default_start = checkpoint.get("checkpoint_date", "")
    if not default_start:
        lookback_dt = datetime.now(timezone.utc) - timedelta(minutes=initial_lookback_minutes)
        default_start = lookback_dt.strftime("%Y-%m-%d")
        logger.info(f"No checkpoint, using initial lookback: {default_start}")

    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    state = _load_state(checkpoint)
    new_state = {}
    cap = max(MAX_SEEN_TOTAL // len(domains), 1)

    all_records = []
    fetch_failed = False

    for domain in domains:
        prev = state.get(domain) or {}
        start = prev.get("date") or default_start
        seen_old = set(prev.get("seen", [])) if prev.get("date") == start else set()

        domain_records, last_checkpoint_date, _, domain_failed = _fetch_domain(
            api_key=api_key,
            domain=domain,
            log_start_date=start,
            log_end_date=today,
            offset=0,
            enable_log_plaintext=enable_log_plaintext,
        )
        fetch_failed = fetch_failed or domain_failed

        new_date = last_checkpoint_date or start
        seen_new = set(seen_old) if new_date == start else set()
        fresh = []
        for rec in domain_records:
            short = _short(rec["record_id"]) if rec.get("record_id") else None
            if short and short in seen_old:
                continue
            fresh.append(rec)
            day = _day(rec)
            if short and (not day or day >= new_date):
                seen_new.add(short)
        all_records.extend(fresh)
        if len(seen_new) > cap:
            logger.warning(f"domain={domain} {len(seen_new)} ids on {new_date}, remembering {cap}")
        new_state[domain] = {"date": new_date, "seen": sorted(seen_new)[:cap]}

    logger.info(f"Fetch complete. domains={len(domains)}, total={len(all_records)}")

    update = {
        "checkpoint_date": max(v["date"] for v in new_state.values()),
        "offset": 0,
        "domain_checkpoints": json.dumps(new_state, separators=(",", ":")),
    }
    if all_records:
        all_records[-1]["_checkpoint_update"] = update
    else:
        # carries the checkpoint only; the caller does not count it as a record
        all_records.append({"_checkpoint_update": update, "_empty_marker": True})

    # A domain that stopped on an HTTP error, a transport error or is_success=false must not
    # read as "no records": the caller counts it under errors (EXP-AZURE-0214).
    if fetch_failed:
        all_records[-1]["_fetch_failed"] = True

    return all_records


def _fetch_domain(api_key: str, domain: str, log_start_date: str, log_end_date: str, offset: int, enable_log_plaintext: bool) -> tuple:
    """Fetch all pages for a single domain. Returns (records, last_checkpoint_date, last_offset, failed)."""
    headers = {"Api-Key": api_key, "Content-Type": "application/json"}
    new_checkpoint_date = log_start_date
    new_offset = offset
    domain_records = []
    page = 0
    fetch_failed = False

    logger.info(f"domain={domain} log_start_date={log_start_date!r} log_end_date={log_end_date!r} offset={offset}")

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
            logger.error(f"domain={domain} request failed: {e}")
            fetch_failed = True
            break

        if resp.status_code == 402:
            # Measured: the customer's key and a made-up key got the same 402 body. An out-of-credit key was not measured.
            logger.error(f"domain={domain} HTTP 402 from the Identity API: the key is unknown, inactive or out of credit; "
                         f"the response does not say which. Check with SOCRadar that it is an active Identity Intelligence key. "
                         f"Body: {resp.text[:200]}")
            fetch_failed = True
            break

        if resp.status_code != 200:
            logger.error(f"domain={domain} API error {resp.status_code}: {resp.text[:200]}")
            fetch_failed = True
            break

        body = resp.json()
        if not body.get("is_success"):
            logger.error(f"domain={domain} is_success=false: {body.get('message', 'unknown')}")
            fetch_failed = True
            break

        payload = body.get("data", {})
        records = payload.get("result", [])
        next_checkpoint = payload.get("checkpoint")  # date of latest record in this page
        next_offset = payload.get("offset")          # None when no more pages

        if not records:
            logger.info(f"domain={domain} no more records")
            break

        page += 1
        for rec in records:
            pw_raw = rec.get("password")
            sanitized = sanitize_password(pw_raw)
            pw_fields = build_law_password_fields(sanitized, enable_log_plaintext)
            del sanitized["_raw"]

            entry = {
                "record_id":        rec.get("id", ""),
                "email":            rec.get("username", ""),  # API field is "username" (masked in the spec, see README)
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

        logger.info(f"domain={domain} page={page}: {len(records)} records")

        if next_checkpoint:
            new_checkpoint_date = next_checkpoint
        if next_offset is not None:
            new_offset = next_offset
        else:
            break

        time.sleep(1)

    return domain_records, new_checkpoint_date, new_offset, fetch_failed
