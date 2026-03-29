"""
Microsoft Sentinel incident creation (optional).
Incident comments NEVER contain password or credential information.
"""

import uuid
import logging
import requests

logger = logging.getLogger("socradar.entra.sentinel")

INCIDENTS_URL = (
    "https://management.azure.com/subscriptions/{subscription_id}"
    "/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights"
    "/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights"
    "/incidents/{incident_id}?api-version=2024-03-01"
)


def _get_mgmt_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Acquire management API token via client credentials."""
    from msal import ConfidentialClientApplication
    app = ConfidentialClientApplication(
        client_id=client_id,
        client_credential=client_secret,
        authority=f"https://login.microsoftonline.com/{tenant_id}"
    )
    result = app.acquire_token_for_client(
        scopes=["https://management.azure.com/.default"]
    )
    if "access_token" not in result:
        raise RuntimeError(f"Failed to acquire management token: {result.get('error_description')}")
    return result["access_token"]


def create_incident(conf: dict, email: str, source: str, severity: str):
    """
    Create a Sentinel incident for a compromised employee credential.

    SECURITY: Only email, source name, and severity are included.
    Password/credential data NEVER appears in incident title, description, or comments.
    """
    workspace_name = conf.get("workspace_name", "")
    workspace_rg = conf.get("workspace_resource_group", "")
    subscription_id = conf.get("subscription_id", "")

    if not all([workspace_name, workspace_rg, subscription_id]):
        logger.warning("[SENTINEL] Incident creation skipped — workspace config incomplete")
        return

    try:
        token = _get_mgmt_token(
            tenant_id=conf["tenant_id"],
            client_id=conf["client_id"],
            client_secret=conf["client_secret"]
        )
    except Exception as e:
        logger.error("[SENTINEL] Token error: %s", e)
        return

    incident_id = str(uuid.uuid4())
    url = INCIDENTS_URL.format(
        subscription_id=subscription_id,
        resource_group=workspace_rg,
        workspace_name=workspace_name,
        incident_id=incident_id
    )

    # Title and description: NO credential data
    title = f"SOCRadar: Leaked credential detected — {source.upper()}"
    description = (
        f"SOCRadar detected a leaked credential for employee account: {email}\n"
        f"Source: {source.upper()}\n"
        f"Severity: {severity}\n\n"
        "Recommended actions: Revoke sessions, reset password, review sign-in activity.\n"
        "Do NOT include credentials in incident comments."
    )

    body = {
        "properties": {
            "title":       title,
            "description": description,
            "severity":    severity.capitalize(),
            "status":      "New",
            "labels": [
                {"labelName": "SOCRadar"},
                {"labelName": source.upper()},
                {"labelName": "LeakedCredential"},
            ]
        }
    }

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type":  "application/json",
    }

    try:
        resp = requests.put(url, json=body, headers=headers, timeout=20)
        if resp.status_code in (200, 201):
            logger.info("[SENTINEL] Incident created for %s (source=%s, severity=%s)", email, source, severity)
        else:
            logger.warning("[SENTINEL] Incident create failed: HTTP %d — %s", resp.status_code, resp.text[:200])
    except requests.RequestException as e:
        logger.error("[SENTINEL] Request error: %s", e)
