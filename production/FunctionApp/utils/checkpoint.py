"""
Table Storage checkpoint management.
One entity per source; the Identity source keeps its per-domain state inside it.

startDate format: YYYY-MM-DD (date string as expected by SOCRadar API).
"""

import time
import logging
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
