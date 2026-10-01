"""
SOCRadar Identity Intelligence Integration — Azure Function App
Timer-triggered function that pulls leaked employee credentials from SOCRadar
Identity Intelligence API and takes automated remediation actions in Microsoft Entra ID.

Source: Identity Intelligence (domain-based query, pay-per-use API key)
"""

import time
import logging
import azure.functions as func
from azure.identity import DefaultAzureCredential

from utils import config as cfg
from utils import checkpoint as cp
from utils.logger import audit_summary

from sources import identity as src_identity

from actions import entra_id as entra
from actions import law_writer as law
from actions import sentinel as sent

logger = logging.getLogger(__name__)
app = func.FunctionApp()


@app.timer_trigger(
    schedule="%POLLING_SCHEDULE%",
    arg_name="timer",
    run_on_startup=True
)
def socradar_identity_import(timer: func.TimerRequest) -> None:
    start_time = time.time()
    logger.info("=== SOCRadar Identity Intelligence Integration started ===")

    if timer.past_due:
        logger.warning("Timer is past due, running anyway")

    conf = cfg.load()
    credential = DefaultAzureCredential()

    if not conf["monitored_domains"]:
        logger.error("MONITORED_DOMAINS not set — nothing to do")
        return

    # Get Entra ID token once
    graph_headers = None
    try:
        graph_token = entra.get_graph_token(
            tenant_id=conf["tenant_id"],
            client_id=conf["client_id"],
            client_secret=conf["client_secret"]
        )
        graph_headers = {
            "Authorization": f"Bearer {graph_token}",
            "Content-Type": "application/json"
        }
    except Exception as e:
        logger.error("[ENTRA] Failed to acquire Graph token — Entra ID actions will be skipped: %s", e)

    logger.info("Monitored domains: %s", conf["monitored_domains"])

    # Load checkpoint and fetch
    src_start = time.time()
    try:
        chk = cp.load(conf["storage_account_name"], credential, "identity")
        employees = src_identity.fetch(conf, chk)
        result = _process_employees(employees, conf, credential, graph_headers)
    except Exception as e:
        logger.error("[IDENTITY] Unhandled error: %s", e, exc_info=True)
        result = {
            "source": "identity", "total": 0, "employees": 0,
            "found": 0, "not_found": 0, "actions": 0, "errors": 1,
            "duration": round(time.time() - src_start, 1)
        }

    result["duration"] = round(time.time() - src_start, 1)

    # Write audit log
    audit_summary(
        source=result["source"], total=result["total"], employees=result["employees"],
        found=result["found"], not_found=result["not_found"], actions=result["actions"],
        errors=result["errors"], duration_sec=result["duration"]
    )

    if conf["workspace_id"] and conf["workspace_key"]:
        law.write_audit(conf, [result])

    total_duration = round(time.time() - start_time, 1)
    logger.info("=== SOCRadar Identity Intelligence Integration finished in %.1fs ===", total_duration)


def _process_employees(employees: list, conf: dict, credential, graph_headers: dict) -> dict:
    """Process fetched Identity Intelligence records: Entra ID lookup + actions + LAW write."""

    found = not_found = actions = errors = 0
    records = []
    hold = False  # set when a record may be lost: the checkpoint must not move past it

    # Extract checkpoint before the loop
    new_checkpoint = employees[-1].get("_checkpoint_update", {}) if employees else {}

    # The source could not finish reading SOCRadar. "0 records, 0 errors" would be a lie:
    # count it, and do not move the checkpoint over a window nobody read (EXP-AZURE-0214).
    fetch_failed = any(e.get("_fetch_failed") for e in employees)
    employees = [e for e in employees if not e.get("_empty_marker")]
    for e in employees:
        e.pop("_fetch_failed", None)
    if fetch_failed:
        logger.error("[IDENTITY] SOCRadar fetch did not finish — counted as an error, checkpoint held")
        errors += 1
        hold = True

    if graph_headers is None:
        logger.error("[ENTRA] No Graph token — no Entra ID action can run; counted as an error, checkpoint held")
        errors += 1
        hold = True

    if conf.get("enable_add_to_group") and not conf.get("security_group_id"):
        logger.warning("[ENTRA] ENABLE_ADD_TO_GROUP is on but SECURITY_GROUP_ID is empty — add-to-group is skipped")

    for emp in employees:
        try:
            email = emp.get("email") or emp.get("user", "")
            if not email:
                continue

            # User lookup in Entra ID (skipped if Graph token unavailable)
            if graph_headers is None:
                emp["entra_status"] = "skipped_no_token"
                emp["actions_taken"] = []
                emp.pop("_checkpoint_update", None)
                records.append(emp)
                continue

            try:
                user_info = entra.lookup_user(email, graph_headers)
            except entra.GraphLookupError as e:
                # Graph did not answer yes or no: not "not_found" (EXP-AZURE-0141)
                logger.error("[ENTRA] lookup failed for %s: %s", email, e)
                errors += 1
                hold = True
                emp["entra_status"] = "lookup_error"
                emp["actions_taken"] = []
                emp.pop("_checkpoint_update", None)
                records.append(emp)
                continue

            if user_info is None:
                not_found += 1
                emp["entra_status"] = "not_found"
                emp["actions_taken"] = []
                emp.pop("_checkpoint_update", None)
                records.append(emp)
                continue

            found += 1
            emp["entra_status"] = "found"
            emp["entra_account_enabled"] = user_info.get("accountEnabled", True)
            emp["entra_user_id"] = user_info.get("id", "")

            emp["severity"] = "MEDIUM"

            # Take actions
            taken = []
            user_id = emp["entra_user_id"]

            if conf["enable_revoke_session"]:
                ok = entra.revoke_sessions(user_id, graph_headers)
                taken.append("revoke_session" if ok else "revoke_session_failed")
                actions += 1

            if conf["enable_add_to_group"] and conf["security_group_id"]:
                ok = entra.add_to_group(user_id, conf["security_group_id"], graph_headers)
                taken.append("add_to_group" if ok else "add_to_group_failed")
                actions += 1

            if conf["enable_disable_account"]:
                ok = entra.disable_account(user_id, graph_headers)
                taken.append("disable_account" if ok else "disable_account_failed")
                actions += 1

            if conf["enable_password_change"]:
                ok = entra.force_password_change(user_id, graph_headers)
                taken.append("force_password_change" if ok else "force_password_change_failed")
                actions += 1

            if conf["enable_confirm_risky"]:
                ok = entra.confirm_compromised(user_id, graph_headers)
                taken.append("confirm_risky" if ok else "confirm_risky_failed")
                actions += 1

            if conf["enable_create_incident"]:
                if not sent.create_incident(conf, email, "identity", emp["severity"]):
                    errors += 1  # visible in the audit row; not a reason to replay the window

            emp["actions_taken"] = taken
            emp.pop("_checkpoint_update", None)
            records.append(emp)

        except Exception as e:
            logger.error("[IDENTITY] Error processing %s: %s", emp.get("email", "?"), e)
            errors += 1
            hold = True

    # Write records to LAW
    if records:
        failed_batches = law.write_records(conf, "identity", records)
        if failed_batches:
            logger.error("[LAW] %d batch(es) were not written — counted as errors, checkpoint held", failed_batches)
            errors += failed_batches
            hold = True

    # Update checkpoint
    if new_checkpoint and not hold:
        cp.save(conf["storage_account_name"], credential, "identity", new_checkpoint)

    return {
        "source":     "identity",
        "total":      len(employees),
        "employees":  len([e for e in employees if e.get("is_employee", True)]),
        "found":      found,
        "not_found":  not_found,
        "actions":    actions,
        "errors":     errors,
        "duration":   0,
    }
