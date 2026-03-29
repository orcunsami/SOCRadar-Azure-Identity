"""
Configuration loader — reads all settings from Azure App Settings (environment variables).
Validates required fields and provides typed accessors.
"""

import os


def _get(key: str, default=None, required: bool = False):
    val = os.environ.get(key, default)
    if required and not val:
        raise EnvironmentError(f"Required App Setting missing: {key}")
    return val


def _bool(key: str, default: bool = False) -> bool:
    val = os.environ.get(key, "").lower()
    if val in ("true", "1", "yes"):
        return True
    if val in ("false", "0", "no"):
        return False
    return default


def _int(key: str, default: int = 0) -> int:
    try:
        return int(os.environ.get(key, str(default)))
    except (ValueError, TypeError):
        return default


def load() -> dict:
    """Load and validate all configuration. Raises EnvironmentError on missing required settings."""
    return {
        # SOCRadar Identity Intelligence API
        "socradar_identity_api_key": _get("SOCRADAR_IDENTITY_API_KEY", required=True),
        "monitored_domains":         [d.strip() for d in _get("MONITORED_DOMAINS", default="").split(",") if d.strip()],

        # Entra ID
        "tenant_id":     _get("ENTRA_TENANT_ID", required=True),
        "client_id":     _get("ENTRA_CLIENT_ID", required=True),
        "client_secret": _get("ENTRA_CLIENT_SECRET", required=True),

        # Action toggles
        "enable_ropc":              _bool("ENABLE_ROPC", False),
        "enable_revoke_session":    _bool("ENABLE_REVOKE_SESSION", True),
        "enable_add_to_group":      _bool("ENABLE_ADD_TO_GROUP", True),
        "enable_password_change":   _bool("ENABLE_PASSWORD_CHANGE", False),
        "enable_disable_account":   _bool("ENABLE_DISABLE_ACCOUNT", False),
        "enable_confirm_risky":     _bool("ENABLE_CONFIRM_RISKY", False),
        "enable_create_incident":   _bool("ENABLE_CREATE_INCIDENT", False),
        "security_group_id":        _get("SECURITY_GROUP_ID", default=""),

        # Password policy
        "enable_log_plaintext_password": _bool("ENABLE_LOG_PLAINTEXT_PASSWORD", False),

        # Log Analytics
        "workspace_id":  _get("WORKSPACE_ID", required=True),
        "workspace_key": _get("WORKSPACE_KEY", required=True),

        # Sentinel (optional, only if create_incident=true)
        "subscription_id":          _get("SUBSCRIPTION_ID", default=""),
        "workspace_name":           _get("WORKSPACE_NAME", default=""),
        "workspace_location":       _get("WORKSPACE_LOCATION", default=""),
        "workspace_resource_group": _get("WORKSPACE_RESOURCE_GROUP", default=""),

        # Storage (for checkpoint)
        "storage_account_name": _get("STORAGE_ACCOUNT_NAME", required=True),

        # Schedule
        "initial_lookback_minutes": _int("INITIAL_LOOKBACK_MINUTES", 600),
    }
