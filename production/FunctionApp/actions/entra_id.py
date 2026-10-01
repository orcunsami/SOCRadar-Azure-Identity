"""
Microsoft Entra ID actions via Microsoft Graph API.
All actions use Application permissions with client credentials flow (MSAL).
"""

import logging
import time
import requests
from urllib.parse import quote
from msal import ConfidentialClientApplication

logger = logging.getLogger("socradar.entra.graph")

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
GRAPH_BETA  = "https://graph.microsoft.com/beta"


class GraphLookupError(RuntimeError):
    """The lookup did not answer yes or no (401/403/429/5xx, transport). Not 'user not found'."""


def get_graph_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Acquire access token for Microsoft Graph using client credentials (app permissions)."""
    app = ConfidentialClientApplication(
        client_id=client_id,
        client_credential=client_secret,
        authority=f"https://login.microsoftonline.com/{tenant_id}"
    )
    result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    if "access_token" not in result:
        err = result.get("error_description", "Unknown error")
        raise RuntimeError(f"Failed to acquire Graph token: {err}")
    logger.info("[ENTRA] Graph token acquired")
    return result["access_token"]


def lookup_user(email: str, graph_headers: dict) -> dict | None:
    """
    Look up a user in Entra ID by email (UPN).
    Returns the user dict, or None only when Graph says 404.
    Raises GraphLookupError for anything else; 429/502/503/504 are retried twice.
    """
    url = f"{GRAPH_BASE}/users/{quote(email, safe='@')}"
    for attempt in range(3):
        try:
            resp = requests.get(url, headers=graph_headers, timeout=15)
        except requests.RequestException as e:
            logger.error("[ENTRA] lookup %s → error: %s", email, e)
            raise GraphLookupError(f"transport error: {e}") from e
        if resp.status_code == 200:
            logger.debug("[ENTRA] lookup %s → found", email)
            return resp.json()
        if resp.status_code == 404:
            logger.debug("[ENTRA] lookup %s → not_found", email)
            return None
        if resp.status_code in (429, 502, 503, 504) and attempt < 2:
            try:
                wait = min(int(resp.headers.get("Retry-After", 2)), 30)
            except (TypeError, ValueError):
                wait = 2
            time.sleep(wait)
            continue
        logger.warning("[ENTRA] lookup %s → HTTP %d", email, resp.status_code)
        raise GraphLookupError(f"HTTP {resp.status_code}")


def revoke_sessions(user_id: str, graph_headers: dict) -> bool:
    """Revoke all sign-in sessions for a user."""
    url = f"{GRAPH_BASE}/users/{user_id}/revokeSignInSessions"
    try:
        resp = requests.post(url, headers=graph_headers, timeout=15)
        ok = resp.status_code in (200, 204)
        logger.info("[ENTRA] revokeSession %s → %s", user_id[:8], "ok" if ok else f"HTTP {resp.status_code}")
        return ok
    except requests.RequestException as e:
        logger.error("[ENTRA] revokeSession %s → error: %s", user_id[:8], e)
        return False


def add_to_group(user_id: str, group_id: str, graph_headers: dict) -> bool:
    """Add user to a security group."""
    url = f"{GRAPH_BASE}/groups/{group_id}/members/$ref"
    body = {"@odata.id": f"{GRAPH_BASE}/directoryObjects/{user_id}"}
    try:
        resp = requests.post(url, headers=graph_headers, json=body, timeout=15)
        # 204 = added, 400 "...already exist for the following modified properties" = already member
        if resp.status_code == 204:
            logger.info("[ENTRA] addToGroup %s → ok", user_id[:8])
            return True
        if resp.status_code == 400 and "already exist" in resp.text.lower():
            logger.info("[ENTRA] addToGroup %s → already member", user_id[:8])
            return True
        logger.warning("[ENTRA] addToGroup %s → HTTP %d: %s", user_id[:8], resp.status_code, resp.text[:100])
        return False
    except requests.RequestException as e:
        logger.error("[ENTRA] addToGroup %s → error: %s", user_id[:8], e)
        return False


def disable_account(user_id: str, graph_headers: dict) -> bool:
    """Disable user account (accountEnabled=false)."""
    url = f"{GRAPH_BASE}/users/{user_id}"
    body = {"accountEnabled": False}
    try:
        resp = requests.patch(url, headers=graph_headers, json=body, timeout=15)
        ok = resp.status_code == 204
        logger.info("[ENTRA] disableAccount %s → %s", user_id[:8], "ok" if ok else f"HTTP {resp.status_code}")
        return ok
    except requests.RequestException as e:
        logger.error("[ENTRA] disableAccount %s → error: %s", user_id[:8], e)
        return False


def force_password_change(user_id: str, graph_headers: dict) -> bool:
    """Force user to change password on next sign-in."""
    url = f"{GRAPH_BASE}/users/{user_id}"
    body = {
        "passwordProfile": {
            "forceChangePasswordNextSignIn": True,
            "forceChangePasswordNextSignInWithMfa": False
        }
    }
    try:
        resp = requests.patch(url, headers=graph_headers, json=body, timeout=15)
        ok = resp.status_code == 204
        logger.info("[ENTRA] forcePasswordChange %s → %s", user_id[:8], "ok" if ok else f"HTTP {resp.status_code}")
        return ok
    except requests.RequestException as e:
        logger.error("[ENTRA] forcePasswordChange %s → error: %s", user_id[:8], e)
        return False


def confirm_compromised(user_id: str, graph_headers: dict) -> bool:
    """
    Confirm user as compromised in Identity Protection.
    Requires IdentityRiskyUser.ReadWrite.All + P1/P2 license.
    """
    url = f"{GRAPH_BETA}/riskyUsers/confirmCompromised"
    body = {"userIds": [user_id]}
    try:
        resp = requests.post(url, headers=graph_headers, json=body, timeout=15)
        ok = resp.status_code == 204
        logger.info("[ENTRA] confirmRisky %s → %s", user_id[:8], "ok" if ok else f"HTTP {resp.status_code}")
        return ok
    except requests.RequestException as e:
        logger.error("[ENTRA] confirmRisky %s → error: %s", user_id[:8], e)
        return False
