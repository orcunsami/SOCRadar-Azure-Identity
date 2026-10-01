#!/usr/bin/env python3
"""A SOCRadar fetch that does not finish must not read as "0 records, 0 errors".

Same defect as the Entra ID integration (EXP-AZURE-0214): an HTTP 401/502 or
is_success=false on the Identity Intelligence endpoint logged an error, returned
an empty list and the audit row said total=0 error_count=0. The fix: the source marks
the returned list, the caller counts one error and does not move the checkpoint.

Needs the azure packages (function_app imports azure.functions).
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "FunctionApp"))

import function_app  # noqa: E402
from sources import identity  # noqa: E402

CONF = {"socradar_identity_api_key": "k", "monitored_domains": ["corp.com"],
        "enable_log_plaintext_password": False, "initial_lookback_minutes": 600,
        "storage_account_name": "st", "workspace_id": "", "workspace_key": ""}


def _resp(status, body=None):
    r = MagicMock(); r.status_code = status; r.text = "err"
    r.json.return_value = body if body is not None else {}
    return r


class SourceMarksFailedFetch(unittest.TestCase):

    def test_http_401_502_and_is_success_false_are_marked(self):
        for resp in (_resp(401), _resp(502), _resp(200, {"is_success": False})):
            with patch.object(identity.requests, "get", return_value=resp):
                records = identity.fetch(CONF, {})
            self.assertTrue(records and records[-1].get("_fetch_failed"), resp.status_code)

    def test_transport_error_is_marked(self):
        with patch.object(identity.requests, "get", side_effect=identity.requests.RequestException("x")):
            records = identity.fetch(CONF, {})
        self.assertTrue(records[-1].get("_fetch_failed"))

    def test_clean_empty_result_is_not_marked(self):
        body = {"is_success": True, "data": {"result": [], "checkpoint": None, "offset": None}}
        with patch.object(identity.requests, "get", return_value=_resp(200, body)):
            records = identity.fetch(CONF, {})
        self.assertFalse(any(r.get("_fetch_failed") for r in records))


class CallerCountsFailedFetch(unittest.TestCase):

    def _run(self, employees):
        saved = []
        for p in (patch.object(function_app.law, "write_records", return_value=0),
                  patch.object(function_app.cp, "save", side_effect=lambda *a: saved.append(a[-1]))):
            p.start(); self.addCleanup(p.stop)
        return function_app._process_employees(employees, CONF, None, {"Authorization": "Bearer x"}), saved

    def test_marked_fetch_counts_one_error_and_holds_the_checkpoint(self):
        marker = {"_checkpoint_update": {"checkpoint_date": "2026-09-01", "offset": 0},
                  "_fetch_failed": True}
        audit, saved = self._run([marker])
        self.assertEqual(audit["errors"], 1, "0 records / 0 errors was the lie in EXP-0214")
        self.assertEqual(saved, [], "checkpoint must not move over a window nobody read")

    def test_unmarked_run_saves_the_checkpoint(self):
        marker = {"_checkpoint_update": {"checkpoint_date": "2026-09-01", "offset": 0}}
        audit, saved = self._run([marker])
        self.assertEqual(audit["errors"], 0)
        self.assertEqual(len(saved), 1)


if __name__ == "__main__":
    unittest.main()
