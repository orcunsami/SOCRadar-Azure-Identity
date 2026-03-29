"""
Table Storage checkpoint management.
Supports per-domain checkpoint for Identity Intelligence.

startDate format: YYYY-MM-DD (date string as expected by SOCRadar API).
"""

import time
import logging
from datetime import datetime, timezone, timedelta
from azure.data.tables import TableServiceClient, TableEntity
from azure.core.exceptions import ResourceNotFoundError

logger = logging.getLogger("socradar.identity.checkpoint")

TABLE_NAME = "IdentityState"


def _get_table(storage_account_name: str, credential):
    url = f"https://{storage_account_name}.table.core.windows.net"
    return TableServiceClient(
        endpoint=url, credential=credential
    ).get_table_client(TABLE_NAME)


def load(storage_account_name: str, credential, source: str) -> dict:
    """
    Load checkpoint for a given source (domain name for Identity).

    Returns dict with source-specific fields, or empty dict if no checkpoint exists.
    """
    client = _get_table(storage_account_name, credential)
    try:
        entity = client.get_entity(partition_key=source, row_key="checkpoint")
        return dict(entity)
    except ResourceNotFoundError:
        logger.info("[CHECKPOINT] No existing checkpoint for source=%s", source)
        return {}


def save(storage_account_name: str, credential, source: str, data: dict):
    """
    Save checkpoint for a given source (domain name for Identity).

    data should contain source-specific fields (no PartitionKey/RowKey needed).
    """
    client = _get_table(storage_account_name, credential)
    entity = TableEntity()
    entity["PartitionKey"] = source
    entity["RowKey"] = "checkpoint"
    entity["last_run_epoch"] = int(time.time())
    for k, v in data.items():
        if k not in ("PartitionKey", "RowKey"):
            entity[k] = v
    client.upsert_entity(entity)
    logger.info("[CHECKPOINT] Saved for source=%s: %s", source, data)


def get_start_date(checkpoint: dict, initial_lookback_minutes: int) -> str:
    """
    Return the startDate string (YYYY-MM-DD) for a fetch cycle.

    Checks both checkpoint_date (Identity API) and last_start_date (standard) keys.
    If neither exists, calculates from initial_lookback_minutes.
    """
    if checkpoint.get("checkpoint_date"):
        return str(checkpoint["checkpoint_date"])
    if checkpoint.get("last_start_date"):
        return str(checkpoint["last_start_date"])
    lookback_dt = datetime.now(timezone.utc) - timedelta(minutes=initial_lookback_minutes)
    return lookback_dt.strftime("%Y-%m-%d")
