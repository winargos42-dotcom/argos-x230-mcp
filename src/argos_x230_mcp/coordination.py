"""Persistent coordination ledger for the existing ARGOS agent-bridge.

SQLite is the authoritative state; asyncio.Queue may wake local workers but
is never used as delivery proof. No agent commands are executed here.
Agents sign state transitions with per-agent secrets provisioned out-of-band.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import stat
import time
from contextlib import contextmanager
from pathlib import Path

TASK_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{3,127}$")
AGENT = re.compile(r"^[a-z][a-z0-9_-]{1,31}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
MAX_TASK_BYTES = 16384
MAX_RESULT_BYTES = 4096
MAX_LEASE = 3600


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def signature(secret_hex: str, action: str, *parts: str) -> str:
    """Deterministic HMAC message for independent authorized agent clients.

    Never include the secret in a chat, tool argument, repository, or journal.
    """
    return hmac.new(
        bytes.fromhex(secret_hex),
        "\n".join((action, *parts)).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _valid(value: str, pattern: re.Pattern, name: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError("Invalid " + name)
    return value


class CoordinationLedger:
    """Fail-closed queue with receipt events; one SQLite DB per workspace."""

    def __init__(self, workspace: Path):
        self.root = Path(workspace).resolve(strict=True)
        self.folder = self.root / "agent-bridge"
        if self.folder.is_symlink():
            raise ValueError("Refusing symlinked agent-bridge")
        self.folder.mkdir(mode=0o700, exist_ok=True)
        if not self.folder.is_dir() or not self.folder.resolve().is_relative_to(self.root):
            raise ValueError("Invalid agent-bridge directory")
        self.db = self.folder / "coordination.sqlite3"
        self.auth = self.folder / ".agents.json"
        if self.db.is_symlink() or self.auth.is_symlink():
            raise ValueError("Refusing symlinked database/auth file")
        with self._connect() as con:
            con.executescript("""
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    recipient TEXT NOT NULL,
                    source_ref TEXT NOT NULL DEFAULT '',
                    instruction TEXT NOT NULL,
                    payload_sha TEXT NOT NULL,
                    state TEXT NOT NULL,
                    retry_safe INTEGER NOT NULL DEFAULT 0,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    lease_until REAL,
                    result_summary TEXT NOT NULL DEFAULT '',
                    artifact_sha TEXT NOT NULL DEFAULT '',
                    artifact_path TEXT NOT NULL DEFAULT '',
                    created REAL NOT NULL,
                    updated REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    task_id TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    event TEXT NOT NULL,
                    evidence_sha TEXT NOT NULL DEFAULT '',
                    at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS ix_tasks_recipient
                  ON tasks(recipient, state, created);
                CREATE INDEX IF NOT EXISTS ix_events_task
                  ON events(task_id, seq);
            """)
        self._limit_permissions()

    @contextmanager
    def _connect(self):
        con = sqlite3.connect(self.db, timeout=8, isolation_level=None)
        try:
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA busy_timeout=8000")
            con.execute("PRAGMA journal_mode=WAL")
            con.execute("PRAGMA synchronous=FULL")
            yield con
        except BaseException:
            if con.in_transaction:
                con.rollback()
            raise
        finally:
            con.close()

    def _limit_permissions(self):
        for file in (self.db, Path(str(self.db) + "-wal"), Path(str(self.db) + "-shm")):
            if file.exists():
                if file.is_symlink():
                    raise ValueError("Refusing symlinked SQLite state")
                file.chmod(0o600)

    def _event(self, con, task_id, actor, event, evidence=""):
        con.execute(
            "INSERT INTO events(task_id,actor,event,evidence_sha,at) VALUES(?,?,?,?,?)",
            (task_id, actor, event, evidence, time.time()),
        )

    def _row(self, con, task_id):
        row = con.execute("SELECT * FROM tasks WHERE task_id=?", (task_id,)).fetchone()
        if row is None:
            raise KeyError("Unknown task")
        return row

    def _key(self, agent: str) -> str:
        _valid(agent, AGENT, "agent")
        if not self.auth.is_file() or stat.S_IMODE(self.auth.stat().st_mode) & 0o077:
            raise PermissionError("Agent credentials not provisioned securely")
        data = json.loads(self.auth.read_text(encoding="utf-8"))
        key = data.get(agent)
        if not isinstance(key, str) or not HEX64.fullmatch(key):
            raise PermissionError("Agent key not provisioned")
        return key

    def _check(self, row, action, provided, *extra):
        if not isinstance(provided, str) or not HEX64.fullmatch(provided):
            raise PermissionError("Invalid agent proof")
        expected = signature(
            self._key(row["recipient"]), action,
            row["task_id"], row["payload_sha"], *extra
        )
        if not hmac.compare_digest(expected, provided):
            raise PermissionError("Invalid agent proof")

    def submit(self, task_id: str, recipient: str, instruction: str,
               source_ref: str = "", retry_safe: bool = False) -> dict:
        """Idempotent by exact ID, recipient and payload. Does NOT mean delivered."""
        _valid(task_id, TASK_ID, "task_id")
        _valid(recipient, AGENT, "recipient")
        if not isinstance(instruction, str) or not instruction.strip():
            raise ValueError("Empty instruction")
        if len(instruction.encode("utf-8")) > MAX_TASK_BYTES:
            raise ValueError("Instruction too large")
        if not isinstance(source_ref, str) or len(source_ref) > 160:
            raise ValueError("Invalid source_ref")
        content_sha = digest(instruction.encode("utf-8"))
        now = time.time()
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            previous = con.execute(
                "SELECT * FROM tasks WHERE task_id=?", (task_id,)
            ).fetchone()
            if previous:
                if (previous["recipient"], previous["payload_sha"],
                    previous["source_ref"], bool(previous["retry_safe"])) != (
                    recipient, content_sha, source_ref, bool(retry_safe)):
                    con.execute("ROLLBACK")
                    raise ValueError("Conflicting task_id; refusing duplicate work")
                con.execute("COMMIT")
                return {"task_id": task_id, "state": previous["state"],
                        "created": False, "payload_sha": content_sha}
            con.execute(
                """INSERT INTO tasks(task_id,recipient,source_ref,instruction,payload_sha,
                    state,retry_safe,created,updated)
                    VALUES(?,?,?,?,?,'QUEUED',?,?,?)""",
                (task_id, recipient, source_ref, instruction, content_sha,
                 int(bool(retry_safe)), now, now),
            )
            self._event(con, task_id, "coordinator", "SUBMITTED", content_sha)
            con.execute("COMMIT")
        self._limit_permissions()
        return {"task_id": task_id, "state": "QUEUED",
                "created": True, "payload_sha": content_sha}

    def poll(self, agent: str, proof: str, limit: int = 10) -> list[dict]:
        """An agent receives only its own tasks, without claiming execution."""
        _valid(agent, AGENT, "agent")
        if not 1 <= limit <= 20:
            raise ValueError("limit must be 1..20")
        if not isinstance(proof, str) or not HEX64.fullmatch(proof):
            raise PermissionError("Invalid agent proof")
        if not hmac.compare_digest(signature(self._key(agent), "poll", agent), proof):
            raise PermissionError("Invalid agent proof")
        with self._connect() as con:
            rows = con.execute(
                """SELECT task_id,recipient,instruction,payload_sha,source_ref
                   FROM tasks WHERE recipient=? AND state='QUEUED'
                   ORDER BY created LIMIT ?""", (agent, limit)
            ).fetchall()
            return [dict(row) for row in rows]

    def transition(self, task_id: str, action: str, proof: str,
                   lease_seconds: int = 900, result: str = "",
                   artifact_sha: str = "", artifact_path: str = "") -> dict:
        """Only a cryptographically authenticated agent changes its own state.

        COMPLETE is merely a report. VERIFIED requires local independent SHA.
        """
        _valid(task_id, TASK_ID, "task_id")
        if action not in ("ack", "start", "complete", "fail"):
            raise ValueError("Unsupported transition")
        if not isinstance(lease_seconds, int) or not 30 <= lease_seconds <= MAX_LEASE:
            raise ValueError("Invalid lease")
        if not isinstance(result, str) or len(result.encode("utf-8")) > MAX_RESULT_BYTES:
            raise ValueError("Result too large")
        if action in ("complete", "fail") and not result.strip():
            raise ValueError("Result evidence required")
        if action == "complete" and not HEX64.fullmatch(artifact_sha):
            raise ValueError("Artifact SHA-256 required")
        if artifact_path and (len(artifact_path) > 240 or
                              Path(artifact_path).is_absolute() or
                              ".." in Path(artifact_path).parts):
            raise ValueError("Artifact path must be workspace-relative")
        result_sha = digest(result.encode("utf-8"))
        evidence = [result_sha, artifact_sha, artifact_path] if action == "complete" else (
            [result_sha] if action == "fail" else [])
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            row = self._row(con, task_id)
            self._check(row, action, proof, *evidence)
            from_state, to_state = {
                "ack": ("QUEUED", "ACKED"),
                "start": ("ACKED", "RUNNING"),
                "complete": ("RUNNING", "DONE_REPORTED"),
                "fail": ("RUNNING", "FAILED"),
            }[action]
            if row["state"] != from_state:
                if row["state"] == to_state:
                    con.execute("COMMIT")
                    return {"task_id": task_id, "state": to_state, "changed": False}
                raise ValueError("Illegal state transition")
            now = time.time()
            con.execute(
                """UPDATE tasks SET state=?, lease_until=?, attempts=attempts+?,
                    result_summary=?, artifact_sha=?, artifact_path=?, updated=?
                    WHERE task_id=?""",
                (to_state, now + lease_seconds if action in ("ack", "start") else None,
                 int(action == "ack"), result if action in ("complete", "fail") else "",
                 artifact_sha if action == "complete" else "",
                 artifact_path if action == "complete" else "", now, task_id),
            )
            self._event(con, task_id, row["recipient"], to_state,
                        artifact_sha if action == "complete" else result_sha)
            con.execute("COMMIT")
        return {"task_id": task_id, "state": to_state, "changed": True}

    def verify(self, task_id: str) -> dict:
        """Do not call a reported result verified until the artifact matches."""
        _valid(task_id, TASK_ID, "task_id")
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            row = self._row(con, task_id)
            if row["state"] == "VERIFIED":
                con.execute("COMMIT")
                return {"task_id": task_id, "state": "VERIFIED", "changed": False}
            if row["state"] != "DONE_REPORTED":
                raise ValueError("Task not ready for artifact verification")
            p = self.root / row["artifact_path"]
            if (not row["artifact_path"] or p.is_symlink() or not p.is_file() or
                    not p.resolve().is_relative_to(self.root)):
                raise ValueError("Verified workspace artifact required")
            # Bound hashing memory without restricting artifact file size.
            h = hashlib.sha256()
            with p.open("rb") as file:
                for block in iter(lambda: file.read(65536), b""):
                    h.update(block)
            if not hmac.compare_digest(h.hexdigest(), row["artifact_sha"]):
                raise ValueError("Artifact checksum mismatch")
            con.execute("UPDATE tasks SET state='VERIFIED',updated=? WHERE task_id=?",
                        (time.time(), task_id))
            self._event(con, task_id, "coordinator", "VERIFIED", h.hexdigest())
            con.execute("COMMIT")
            return {"task_id": task_id, "state": "VERIFIED", "changed": True}

    def reconcile_expired(self, now: float | None = None) -> dict:
        """Never blindly repeat potentially side-effecting agent actions."""
        now = time.time() if now is None else float(now)
        states = {"requeued": [], "needs_owner": []}
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            rows = con.execute(
                """SELECT * FROM tasks WHERE state IN ('ACKED','RUNNING')
                   AND lease_until IS NOT NULL AND lease_until <= ?""", (now,)
            ).fetchall()
            for row in rows:
                retry = bool(row["retry_safe"]) and row["attempts"] < 3
                new_state = "QUEUED" if retry else "NEEDS_OWNER"
                con.execute(
                    "UPDATE tasks SET state=?,lease_until=NULL,updated=? WHERE task_id=?",
                    (new_state, now, row["task_id"]))
                self._event(con, row["task_id"], "coordinator",
                            "LEASE_EXPIRED_" + new_state)
                states["requeued" if retry else "needs_owner"].append(row["task_id"])
            con.execute("COMMIT")
        return states

    def get(self, task_id: str) -> dict:
        _valid(task_id, TASK_ID, "task_id")
        with self._connect() as con:
            row = self._row(con, task_id)
            events = con.execute(
                """SELECT actor,event,evidence_sha,at FROM events
                   WHERE task_id=? ORDER BY seq DESC LIMIT 30""", (task_id,)
            ).fetchall()
            return {"task": dict(row), "events": [dict(e) for e in events]}

    def list(self, limit: int = 50) -> list[dict]:
        if not 1 <= limit <= 100:
            raise ValueError("limit must be 1..100")
        with self._connect() as con:
            rows = con.execute(
                """SELECT task_id,recipient,source_ref,state,attempts,payload_sha,
                   artifact_sha,created,updated FROM tasks ORDER BY updated DESC LIMIT ?""",
                (limit,),
            ).fetchall()
            return [dict(row) for row in rows]

    def observe_legacy(self, relative_path: str) -> dict:
        """Index existing inbox receipt as unverified evidence, not as an ACK."""
        p = Path(relative_path)
        if (not isinstance(relative_path, str) or p.is_absolute()
                or ".." in p.parts or len(relative_path) > 230
                or len(p.parts) != 3 or p.parts[0] != "agent-bridge"
                or p.parts[1] not in ("inbox_argos", "archive")):
            raise ValueError("Only existing ARGOS inbox receipts are accepted")
        path = self.root / p
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
            raise ValueError("Invalid legacy receipt file")
        raw = path.read_bytes()
        data = json.loads(raw)
        if not isinstance(data, dict) or data.get("kind") != "answer":
            raise ValueError("Not an answer receipt")
        refs = data.get("ref", [])
        refs = refs if isinstance(refs, list) else [refs]
        with self._connect() as con:
            con.execute("BEGIN IMMEDIATE")
            rows = con.execute(
                "SELECT task_id,source_ref FROM tasks WHERE source_ref!=''"
            ).fetchall()
            matches = [x["task_id"] for x in rows if x["source_ref"] in refs]
            for task_id in matches:
                observed = con.execute(
                    """SELECT 1 FROM events WHERE task_id=? AND event='LEGACY_OBSERVED_UNVERIFIED'
                       AND evidence_sha=?""", (task_id, digest(raw))
                ).fetchone()
                if not observed:
                    self._event(con, task_id, "legacy_bridge",
                                "LEGACY_OBSERVED_UNVERIFIED", digest(raw))
            con.execute("COMMIT")
        return {"matched": matches, "receipt_sha": digest(raw),
                "state_changed": False, "trust": "UNVERIFIED"}


def register_coordination_tools(mcp, workspace: Path) -> None:
    """MCP adapter; no arbitrary shell and no automatic agent impersonation."""
    def store():
        return CoordinationLedger(workspace)

    @mcp.tool()
    def coordination_submit(task_id: str, recipient: str, instruction: str,
                            source_ref: str = "", retry_safe: bool = False) -> dict:
        """Queue one task for an existing agent; QUEUED is not delivered or ACKED."""
        return store().submit(task_id, recipient, instruction, source_ref, retry_safe)

    @mcp.tool()
    def coordination_poll(agent: str, proof: str, limit: int = 10) -> list[dict]:
        """Allow a separately credentialed agent to read only its own queue."""
        return store().poll(agent, proof, limit)

    @mcp.tool()
    def coordination_agent_event(task_id: str, action: str, proof: str,
                                 lease_seconds: int = 900, result: str = "",
                                 artifact_sha: str = "",
                                 artifact_path: str = "") -> dict:
        """Authenticated ACK/START/COMPLETE/FAIL; never executes task content."""
        return store().transition(task_id, action, proof, lease_seconds,
                                  result, artifact_sha, artifact_path)

    @mcp.tool()
    def coordination_verify(task_id: str) -> dict:
        """Promote agent result only after checking a local workspace artifact SHA."""
        return store().verify(task_id)

    @mcp.tool()
    def coordination_status(task_id: str) -> dict:
        """Read task and immutable event receipts, without trusting generic answers."""
        return store().get(task_id)

    @mcp.tool()
    def coordination_list(limit: int = 50) -> list[dict]:
        """Read the bounded persistent coordination queue."""
        return store().list(limit)

    @mcp.tool()
    def coordination_reconcile_expired() -> dict:
        """Requeue only read-only/idempotent work; owner review otherwise."""
        return store().reconcile_expired()

    @mcp.tool()
    def coordination_observe_legacy(relative_path: str) -> dict:
        """Index a Hermes/ARGOS inbox answer as unverified evidence only."""
        return store().observe_legacy(relative_path)
