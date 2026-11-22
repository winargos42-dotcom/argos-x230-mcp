"""Durable ARGOS coordination tests: no external services or secrets."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from argos_x230_mcp.coordination import (
    CoordinationLedger, register_coordination_tools, signature,
)


class FakeMCP:
    def __init__(self):
        self.registered = {}

    def tool(self):
        def decorate(fn):
            self.registered[fn.__name__] = fn
            return fn
        return decorate


class CoordinationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="argos-coord-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = CoordinationLedger(self.root)
        self.secrets = {"opencode": "11" * 32, "zcode": "22" * 32}
        self.store.auth.write_text(json.dumps(self.secrets))
        self.store.auth.chmod(0o600)

    def submit(self, task_id="ZAT-12345", agent="opencode",
               retry_safe=True, source_ref=""):
        return self.store.submit(
            task_id, agent, "Read the code and produce an artifact.",
            source_ref=source_ref, retry_safe=retry_safe
        )

    def proof(self, task_id, action, result="", artifact_sha="", artifact_path=""):
        row = self.store.get(task_id)["task"]
        parts = [hashlib.sha256(result.encode()).hexdigest(), artifact_sha,
                 artifact_path] if action == "complete" else (
                 [hashlib.sha256(result.encode()).hexdigest()] if action == "fail"
                 else [])
        return signature(self.secrets[row["recipient"]],
                         action, task_id, row["payload_sha"], *parts)

    def transition(self, task_id, action, result="", sha="", path=""):
        return self.store.transition(
            task_id, action, self.proof(task_id, action, result, sha, path),
            result=result, artifact_sha=sha, artifact_path=path)

    def test_idempotent_submit_and_reject_conflicts(self):
        first = self.submit()
        self.assertEqual(first["state"], "QUEUED")
        second = self.submit()
        self.assertFalse(second["created"])
        self.assertEqual(len(self.store.list()), 1)
        with self.assertRaisesRegex(ValueError, "Conflicting"):
            self.store.submit("ZAT-12345", "zcode", "Different instructions")
        self.assertEqual(self.store.get("ZAT-12345")["task"]["state"], "QUEUED")

    def test_no_ack_without_agent_credentials(self):
        self.submit()
        with self.assertRaises(PermissionError):
            self.store.transition("ZAT-12345", "ack", "0" * 64)
        self.store.auth.chmod(0o644)
        with self.assertRaises(PermissionError):
            self.store.transition("ZAT-12345", "ack", self.proof("ZAT-12345", "ack"))
        self.assertEqual(self.store.get("ZAT-12345")["task"]["state"], "QUEUED")

    def test_agent_poll_is_authenticated_and_scoped(self):
        self.submit()
        self.submit("ZAT-ZCODE", agent="zcode")
        with self.assertRaises(PermissionError):
            self.store.poll("opencode", "0" * 64)
        tasks = self.store.poll("opencode", signature(self.secrets["opencode"],
                                                     "poll", "opencode"))
        self.assertEqual([t["task_id"] for t in tasks], ["ZAT-12345"])
        self.assertEqual(self.store.get("ZAT-12345")["task"]["state"], "QUEUED")

    def test_real_transition_requires_ack_then_start(self):
        self.submit()
        with self.assertRaisesRegex(ValueError, "Illegal"):
            self.transition("ZAT-12345", "start")
        self.assertTrue(self.transition("ZAT-12345", "ack")["changed"])
        self.assertFalse(self.transition("ZAT-12345", "ack")["changed"])
        self.assertTrue(self.transition("ZAT-12345", "start")["changed"])
        self.assertEqual(self.store.get("ZAT-12345")["task"]["attempts"], 1)

    def test_complete_only_reported_until_artifact_verified(self):
        self.submit()
        self.transition("ZAT-12345", "ack")
        self.transition("ZAT-12345", "start")
        artifact = self.root / "output.txt"
        artifact.write_bytes(b"verified ZomATON code")
        sha = hashlib.sha256(artifact.read_bytes()).hexdigest()
        reported = self.transition("ZAT-12345", "complete", "Tests passed",
                                   sha, "output.txt")
        self.assertEqual(reported["state"], "DONE_REPORTED")
        self.assertEqual(self.store.verify("ZAT-12345")["state"], "VERIFIED")
        self.assertFalse(self.store.verify("ZAT-12345")["changed"])
        self.assertEqual(self.store.get("ZAT-12345")["events"][0]["event"], "VERIFIED")

    def test_invalid_checksum_does_not_complete_verification(self):
        self.submit()
        self.transition("ZAT-12345", "ack")
        self.transition("ZAT-12345", "start")
        (self.root / "x.txt").write_text("not equal")
        self.transition("ZAT-12345", "complete", "report", "1" * 64, "x.txt")
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.store.verify("ZAT-12345")
        self.assertEqual(self.store.get("ZAT-12345")["task"]["state"], "DONE_REPORTED")

    def test_fail_only_agent_can_report_and_expired_mutations_need_owner(self):
        self.submit(retry_safe=False)
        self.transition("ZAT-12345", "ack")
        self.transition("ZAT-12345", "start")
        out = self.store.reconcile_expired(now=9999999999.0)
        self.assertEqual(out["needs_owner"], ["ZAT-12345"])
        self.assertEqual(self.store.get("ZAT-12345")["task"]["state"], "NEEDS_OWNER")

    def test_expired_safe_task_requeued_once_and_survives_restart(self):
        self.submit()
        self.transition("ZAT-12345", "ack")
        self.assertEqual(self.store.reconcile_expired(now=9999999999.0)["requeued"],
                         ["ZAT-12345"])
        reopened = CoordinationLedger(self.root)
        self.assertEqual(reopened.get("ZAT-12345")["task"]["state"], "QUEUED")
        self.transition("ZAT-12345", "ack")
        self.transition("ZAT-12345", "start")
        self.assertEqual(self.store.reconcile_expired(now=9999999999.0)["requeued"],
                         ["ZAT-12345"])
        self.transition("ZAT-12345", "ack")
        self.assertEqual(self.store.reconcile_expired(now=9999999999.0)["needs_owner"],
                         ["ZAT-12345"])

    def test_legacy_receipt_is_evidence_not_finished_work(self):
        self.submit(source_ref="20261122T0133Z_reconcile")
        folder = self.root / "agent-bridge" / "inbox_argos"
        folder.mkdir()
        file = folder / "answer_0133.json"
        file.write_text(json.dumps({
            "kind": "answer", "ref": "20261122T0133Z_reconcile",
            "body": "task None, status None, reply empty",
        }))
        result = self.store.observe_legacy("agent-bridge/inbox_argos/answer_0133.json")
        self.assertEqual(result["matched"], ["ZAT-12345"])
        self.assertFalse(result["state_changed"])
        self.assertEqual(self.store.get("ZAT-12345")["task"]["state"], "QUEUED")
        self.assertEqual(self.store.observe_legacy(
            "agent-bridge/inbox_argos/answer_0133.json")["matched"], ["ZAT-12345"])
        self.assertEqual(sum(e["event"] == "LEGACY_OBSERVED_UNVERIFIED"
                             for e in self.store.get("ZAT-12345")["events"]), 1)

    def test_path_traversal_and_symlinks_are_rejected(self):
        self.submit()
        with self.assertRaises(ValueError):
            self.store.observe_legacy("../../outside.json")
        (self.root / "artifact-link").symlink_to(Path(self.tmp.name).parent)
        self.transition("ZAT-12345", "ack")
        self.transition("ZAT-12345", "start")
        with self.assertRaises(ValueError):
            self.store.transition("ZAT-12345", "complete",
                                  self.proof("ZAT-12345", "complete"),
                                  result="done", artifact_sha="0" * 64,
                                  artifact_path="../../secret")
        self.assertEqual(self.store.get("ZAT-12345")["task"]["state"], "RUNNING")

    def test_mcp_registration_no_arbitrary_execution(self):
        api = FakeMCP()
        register_coordination_tools(api, self.root)
        expected = {
            "coordination_submit", "coordination_poll",
            "coordination_agent_event", "coordination_verify",
            "coordination_status", "coordination_list",
            "coordination_reconcile_expired", "coordination_observe_legacy",
        }
        self.assertEqual(set(api.registered), expected)
        enqueued = api.registered["coordination_submit"](
            "ZAT-7777", "opencode", "Generate a result")
        self.assertEqual(enqueued["state"], "QUEUED")
        self.assertEqual(api.registered["coordination_status"](
            "ZAT-7777")["task"]["state"], "QUEUED")


if __name__ == "__main__":
    unittest.main()
