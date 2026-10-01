#!/usr/bin/env python3
"""A run that lost data must not look clean, and must not move the checkpoint.

Audit 0080 (identity.md): a failed LAW write, a Graph 401/403/429/5xx, a missing Graph
token and a per-record exception all ended in errors=0 (or an uncounted error) and a
checkpoint that moved past records nobody stored or actioned. The same checkpoint was
shared by every domain and was only day-resolved, so records came back on every run.

Needs the azure packages (function_app imports azure.functions).
"""

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "FunctionApp"))

import function_app  # noqa: E402
from actions import entra_id, law_writer, sentinel  # noqa: E402
from sources import identity  # noqa: E402

CONF = {"socradar_identity_api_key": "k", "monitored_domains": ["corp.com"],
        "enable_log_plaintext_password": False, "initial_lookback_minutes": 600,
        "storage_account_name": "st", "workspace_id": "w", "workspace_key": "aw==",
        "enable_revoke_session": True, "enable_add_to_group": False,
        "enable_disable_account": False, "enable_password_change": False,
        "enable_confirm_risky": False, "enable_create_incident": False,
        "security_group_id": ""}
HEADERS = {"Authorization": "Bearer x"}
CP = {"_checkpoint_update": {"checkpoint_date": "2026-09-30", "offset": 0}}


def _resp(status, body=None, headers=None, text="err"):
    r = MagicMock(); r.status_code = status; r.text = text; r.headers = headers or {}
    r.json.return_value = body if body is not None else {}
    return r


def _rec(rid, user, day="2026-09-30"):
    return {"id": rid, "username": user, "log_date": day + " 10:00:00",
            "insert_date": day + " 10:00:00", "password": "a****b", "url": "", "country": ""}


def _page(*recs, checkpoint, offset=None):
    return _resp(200, {"is_success": True,
                       "data": {"result": list(recs), "checkpoint": checkpoint, "offset": offset}})


class Pipeline(unittest.TestCase):
    """_process_employees with the Graph and LAW edges replaced; returns (audit, saved)."""

    def _run(self, conf=None, headers=HEADERS, lookup=None, post=True, emps=None):
        saved = []
        emps = emps if emps is not None else [{"email": "a@corp.com", **CP}]
        patches = [
            patch.object(function_app.cp, "save", side_effect=lambda *a: saved.append(a[-1])),
            patch.object(function_app.entra, "lookup_user",
                         side_effect=lookup or (lambda e, h: {"id": "uid-1234567", "accountEnabled": True})),
            patch.object(function_app.entra, "revoke_sessions", return_value=True),
            patch.object(law_writer, "_post", return_value=post),
            patch.object(law_writer.time, "sleep"),
        ]
        for p in patches:
            p.start(); self.addCleanup(p.stop)
        audit = function_app._process_employees(emps, dict(CONF, **(conf or {})), None, headers)
        return audit, saved

    # audit 1
    def test_law_write_failure_counts_an_error_and_holds_the_checkpoint(self):
        audit, saved = self._run(post=False)
        self.assertGreater(audit["errors"], 0)
        self.assertEqual(saved, [], "records that never reached LAW must be fetched again")

    def test_law_write_success_saves_the_checkpoint(self):
        audit, saved = self._run()
        self.assertEqual(audit["errors"], 0)
        self.assertEqual(len(saved), 1)

    # audit 2
    def test_graph_lookup_failure_counts_an_error_and_holds_the_checkpoint(self):
        def boom(e, h):
            raise entra_id.GraphLookupError("HTTP 403")
        audit, saved = self._run(lookup=boom)
        self.assertGreater(audit["errors"], 0)
        self.assertEqual(audit["not_found"], 0, "a 403 is not 'user not in the tenant'")
        self.assertEqual(saved, [])

    def test_genuine_not_found_is_not_an_error(self):
        audit, saved = self._run(lookup=lambda e, h: None)
        self.assertEqual((audit["not_found"], audit["errors"]), (1, 0))
        self.assertEqual(len(saved), 1)

    # audit 3a
    def test_missing_graph_token_counts_an_error_and_holds_the_checkpoint(self):
        audit, saved = self._run(headers=None)
        self.assertGreater(audit["errors"], 0)
        self.assertEqual(saved, [])

    # audit 3b
    def test_per_record_exception_holds_the_checkpoint(self):
        audit, saved = self._run(lookup=lambda e, h: 1 / 0)
        self.assertEqual(audit["errors"], 1)
        self.assertEqual(saved, [])

    # audit 7: an incident that was not created is visible, and is not a reason to replay
    def test_failed_incident_counts_an_error_but_does_not_hold_the_checkpoint(self):
        with patch.object(function_app.sent, "create_incident", return_value=False):
            audit, saved = self._run(conf={"enable_create_incident": True})
        self.assertEqual(audit["errors"], 1)
        self.assertEqual(len(saved), 1)

    # audit 14
    def test_clean_empty_run_reports_zero_records(self):
        body = {"is_success": True, "data": {"result": [], "checkpoint": None, "offset": None}}
        with patch.object(identity.requests, "get", return_value=_resp(200, body)):
            emps = identity.fetch(CONF, {})
        audit, saved = self._run(emps=emps)
        self.assertEqual((audit["total"], audit["employees"], audit["errors"]), (0, 0, 0))
        self.assertEqual(len(saved), 1, "an empty window still moves the checkpoint")


class GraphLookup(unittest.TestCase):

    def test_non_404_failures_raise(self):
        for status in (401, 403, 500):
            with patch.object(entra_id.requests, "get", return_value=_resp(status)):
                with self.assertRaises(entra_id.GraphLookupError, msg=status):
                    entra_id.lookup_user("a@corp.com", HEADERS)

    def test_transport_error_raises(self):
        with patch.object(entra_id.requests, "get",
                          side_effect=entra_id.requests.RequestException("x")):
            with self.assertRaises(entra_id.GraphLookupError):
                entra_id.lookup_user("a@corp.com", HEADERS)

    def test_404_is_none_and_200_is_the_user(self):
        with patch.object(entra_id.requests, "get", return_value=_resp(404)):
            self.assertIsNone(entra_id.lookup_user("a@corp.com", HEADERS))
        with patch.object(entra_id.requests, "get", return_value=_resp(200, {"id": "u"})):
            self.assertEqual(entra_id.lookup_user("a@corp.com", HEADERS), {"id": "u"})

    def test_throttling_is_retried_with_retry_after(self):
        seq = [_resp(429, headers={"Retry-After": "3"}), _resp(200, {"id": "u"})]
        with patch.object(entra_id.requests, "get", side_effect=seq), \
                patch.object(entra_id.time, "sleep") as sleep:
            self.assertEqual(entra_id.lookup_user("a@corp.com", HEADERS), {"id": "u"})
        sleep.assert_called_once_with(3)

    def test_throttling_that_never_clears_raises(self):
        with patch.object(entra_id.requests, "get", return_value=_resp(429)), \
                patch.object(entra_id.time, "sleep"):
            with self.assertRaises(entra_id.GraphLookupError):
                entra_id.lookup_user("a@corp.com", HEADERS)

    # audit 22
    def test_email_is_encoded_in_the_url(self):
        with patch.object(entra_id.requests, "get", return_value=_resp(404)) as get:
            entra_id.lookup_user("a/b?c#d@corp.com", HEADERS)
        url = get.call_args[0][0]
        self.assertTrue(url.endswith("/users/a%2Fb%3Fc%23d@corp.com"), url)

    # audit 9
    def test_already_a_member_is_success_whatever_the_wording(self):
        text = "One or more added object references already exist for the following modified properties: 'members'."
        with patch.object(entra_id.requests, "post", return_value=_resp(400, text=text)):
            self.assertTrue(entra_id.add_to_group("uid-1234567", "g", HEADERS))
        with patch.object(entra_id.requests, "post", return_value=_resp(400, text="Bad")):
            self.assertFalse(entra_id.add_to_group("uid-1234567", "g", HEADERS))


class Writers(unittest.TestCase):

    def test_write_records_reports_failed_batches(self):
        recs = [{"email": str(i)} for i in range(150)]
        with patch.object(law_writer, "_post", side_effect=[True, False]), \
                patch.object(law_writer.time, "sleep"):
            self.assertEqual(law_writer.write_records(CONF, "identity", recs), 1)
        with patch.object(law_writer, "_post", return_value=True), \
                patch.object(law_writer.time, "sleep"):
            self.assertEqual(law_writer.write_records(CONF, "identity", recs), 0)

    def test_write_audit_reports_failure(self):
        with patch.object(law_writer, "_post", return_value=False):
            self.assertFalse(law_writer.write_audit(CONF, [{"source": "identity"}]))

    def test_incident_failure_is_returned_and_labels_carry_a_type(self):
        conf = dict(CONF, workspace_name="ws", workspace_resource_group="rg", subscription_id="s",
                    tenant_id="t", client_id="c", client_secret="x")
        with patch.object(sentinel, "_get_mgmt_token", return_value="tok"), \
                patch.object(sentinel.requests, "put", return_value=_resp(403)) as put:
            self.assertFalse(sentinel.create_incident(conf, "a@corp.com", "identity", "MEDIUM"))
            labels = put.call_args[1]["json"]["properties"]["labels"]
        self.assertTrue(all(l.get("labelType") == "User" for l in labels), labels)
        with patch.object(sentinel, "_get_mgmt_token", return_value="tok"), \
                patch.object(sentinel.requests, "put", return_value=_resp(201)):
            self.assertTrue(sentinel.create_incident(conf, "a@corp.com", "identity", "MEDIUM"))


class Checkpoint(unittest.TestCase):

    def _fetch(self, pages, chk=None, domains=("a.com", "b.com")):
        calls = []

        def get(url, headers=None, params=None, timeout=None):
            calls.append(dict(params))
            return pages[params["query"]].pop(0)
        with patch.object(identity.requests, "get", side_effect=get), \
                patch.object(identity.time, "sleep"):
            recs = identity.fetch(dict(CONF, monitored_domains=list(domains)), chk or {})
        return recs, calls

    # audit 4
    def test_each_domain_keeps_its_own_checkpoint(self):
        pages = {"a.com": [_page(_rec("A1", "x@a.com", "2026-09-30"), checkpoint="2026-09-30")],
                 "b.com": [_page(_rec("B1", "y@b.com", "2026-09-01"), checkpoint="2026-09-01")]}
        recs, _ = self._fetch(pages, {"checkpoint_date": "2026-08-01"})
        update = recs[-1]["_checkpoint_update"]
        self.assertEqual(update["checkpoint_date"], "2026-09-30")
        pages = {"a.com": [_page(checkpoint=None)], "b.com": [_page(checkpoint=None)]}
        _, calls = self._fetch(pages, update)
        start = {c["query"]: c["log_start_date"] for c in calls}
        self.assertEqual(start, {"a.com": "2026-09-30", "b.com": "2026-09-01"},
                         "a quiet domain must not be pushed forward, a busy one must not be pulled back")

    def test_a_quiet_domain_does_not_pull_the_checkpoint_back(self):
        pages = {"a.com": [_page(_rec("A1", "x@a.com"), checkpoint="2026-09-30")],
                 "b.com": [_page(checkpoint=None)]}
        recs, _ = self._fetch(pages, {"checkpoint_date": "2026-08-01"})
        self.assertEqual(recs[-1]["_checkpoint_update"]["checkpoint_date"], "2026-09-30")

    # audit 5
    def test_records_already_seen_on_the_checkpoint_day_are_not_returned_again(self):
        first = {"a.com": [_page(_rec("A1", "x@a.com"), _rec("A2", "y@a.com"), checkpoint="2026-09-30")]}
        recs, _ = self._fetch(first, {}, domains=("a.com",))
        self.assertEqual([r["record_id"] for r in recs if "record_id" in r], ["A1", "A2"])
        update = recs[-1]["_checkpoint_update"]
        # the API returns the whole day again, plus one record that arrived since
        again = {"a.com": [_page(_rec("A1", "x@a.com"), _rec("A2", "y@a.com"), _rec("A3", "z@a.com"),
                                 checkpoint="2026-09-30")]}
        recs, _ = self._fetch(again, update, domains=("a.com",))
        self.assertEqual([r["record_id"] for r in recs if "record_id" in r], ["A3"])
        # A1/A2 stay remembered for the run after that
        update = recs[-1]["_checkpoint_update"]
        third = {"a.com": [_page(_rec("A1", "x@a.com"), _rec("A3", "z@a.com"), checkpoint="2026-09-30")]}
        recs, _ = self._fetch(third, update, domains=("a.com",))
        self.assertEqual([r for r in recs if "record_id" in r], [])

    def test_seen_records_of_an_older_day_are_forgotten(self):
        first = {"a.com": [_page(_rec("A1", "x@a.com", "2026-09-29"), checkpoint="2026-09-29")]}
        recs, _ = self._fetch(first, {}, domains=("a.com",))
        nxt = {"a.com": [_page(_rec("A9", "q@a.com", "2026-09-30"), checkpoint="2026-09-30")]}
        recs, _ = self._fetch(nxt, recs[-1]["_checkpoint_update"], domains=("a.com",))
        state = json.loads(recs[-1]["_checkpoint_update"]["domain_checkpoints"])
        self.assertEqual(state["a.com"]["date"], "2026-09-30")
        self.assertEqual(len(state["a.com"]["seen"]), 1)


if __name__ == "__main__":
    unittest.main()
