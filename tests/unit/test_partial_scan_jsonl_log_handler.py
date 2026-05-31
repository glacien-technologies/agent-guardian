"""Unit tests for ``JsonlLogHandler`` + ``install_jsonl_log_handler``.

Covers the Python-logging -> events.jsonl bridge that drives the
CLI-style running log in the Executive Logs tab. See
``src/agent_guardian/server/partial_scan.py``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from agent_guardian.server.partial_scan import (
    JsonlLogHandler,
    install_jsonl_log_handler,
)


def _read_events(path: Path) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        out.append(json.loads(line))
    return out


def test_jsonl_log_handler_writes_log_kind_records(tmp_path: Path) -> None:
    """A record on an allowlisted logger lands as kind='log' in events.jsonl."""
    handler = JsonlLogHandler(tmp_path)
    logger = logging.getLogger("agent_guardian.test_target_a")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    try:
        logger.info("hello world")
        logger.warning("be careful")
        logger.error("boom")
    finally:
        logger.removeHandler(handler)

    rows = _read_events(tmp_path / "events.jsonl")
    assert len(rows) == 3
    for r in rows:
        assert r["kind"] == "log"
        assert r["agent"] is None
        assert r["asi"] is None
        assert r["decision"] is None
        assert isinstance(r["timestamp"], str)
        payload = r["payload"]
        assert isinstance(payload, dict)
        assert payload["logger"] == "agent_guardian.test_target_a"
    assert rows[0]["payload"]["level"] == "INFO"
    assert rows[0]["payload"]["message"] == "hello world"
    assert rows[1]["payload"]["level"] == "WARNING"
    assert rows[2]["payload"]["level"] == "ERROR"


def test_jsonl_log_handler_captures_exc_info(tmp_path: Path) -> None:
    """``logger.exception`` records carry a formatted traceback in payload."""
    handler = JsonlLogHandler(tmp_path)
    logger = logging.getLogger("agent_guardian.test_target_b")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    try:
        try:
            raise RuntimeError("kaboom")
        except RuntimeError:
            logger.exception("caught it")
    finally:
        logger.removeHandler(handler)

    rows = _read_events(tmp_path / "events.jsonl")
    assert len(rows) == 1
    payload = rows[0]["payload"]
    assert isinstance(payload, dict)
    assert "exc_info" in payload
    assert "RuntimeError" in str(payload["exc_info"])
    assert "kaboom" in str(payload["exc_info"])


def test_jsonl_log_handler_drops_records_outside_allowlist(tmp_path: Path) -> None:
    """A record on a logger whose name is not in the allowlist is dropped."""
    handler = JsonlLogHandler(tmp_path, allowlist=("agent_guardian",))
    blocked = logging.getLogger("urllib3.connectionpool")
    allowed = logging.getLogger("agent_guardian.core.swarm")
    blocked.setLevel(logging.DEBUG)
    allowed.setLevel(logging.DEBUG)
    blocked.addHandler(handler)
    allowed.addHandler(handler)
    try:
        blocked.info("starting new HTTPS connection")
        allowed.info("phase=recon start")
    finally:
        blocked.removeHandler(handler)
        allowed.removeHandler(handler)

    rows = _read_events(tmp_path / "events.jsonl")
    assert len(rows) == 1
    assert rows[0]["payload"]["logger"] == "agent_guardian.core.swarm"


def test_jsonl_log_handler_allowlist_matches_exact_and_dotted(tmp_path: Path) -> None:
    """Prefix matching is strict: ``httpx`` matches itself and ``httpx.client``,
    but not ``httpx_clone`` or ``otherhttpx``."""
    handler = JsonlLogHandler(tmp_path, allowlist=("httpx",))
    exact = logging.getLogger("httpx")
    dotted = logging.getLogger("httpx.client")
    bogus = logging.getLogger("httpx_clone")
    for lg in (exact, dotted, bogus):
        lg.setLevel(logging.DEBUG)
        lg.addHandler(handler)
    try:
        exact.info("exact")
        dotted.info("dotted")
        bogus.info("bogus")
    finally:
        for lg in (exact, dotted, bogus):
            lg.removeHandler(handler)

    rows = _read_events(tmp_path / "events.jsonl")
    loggers = {r["payload"]["logger"] for r in rows}
    assert loggers == {"httpx", "httpx.client"}


def test_jsonl_log_handler_touches_events_file_on_init(tmp_path: Path) -> None:
    """The file is created up-front so the dashboard sees it even pre-emit."""
    target = tmp_path / "scan"
    handler = JsonlLogHandler(target)
    assert (target / "events.jsonl").is_file()
    # And it is initially empty.
    assert (target / "events.jsonl").read_text(encoding="utf-8") == ""
    # Touch the handler attribute to avoid unused-var linter.
    assert handler.scan_dir == target


def test_jsonl_log_handler_message_includes_log_args_formatting(tmp_path: Path) -> None:
    """``logger.info("got %s", "x")`` formats via record.getMessage()."""
    handler = JsonlLogHandler(tmp_path)
    logger = logging.getLogger("agent_guardian.test_target_c")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    try:
        logger.info("got %s in %d ms", "result", 42)
    finally:
        logger.removeHandler(handler)
    rows = _read_events(tmp_path / "events.jsonl")
    assert rows[0]["payload"]["message"] == "got result in 42 ms"


def test_install_jsonl_log_handler_attaches_to_root_logger(tmp_path: Path) -> None:
    """The installer attaches a handler the root logger picks up."""
    root = logging.getLogger()
    pre = list(root.handlers)
    handler = install_jsonl_log_handler(tmp_path)
    # Lower the test logger's level so INFO records actually propagate to
    # the root handler — the system-wide root level defaults to WARNING in
    # the test harness, which would otherwise drop the message before it
    # reaches the JsonlLogHandler.
    target_logger = logging.getLogger("agent_guardian.test_target_d")
    prior_level = target_logger.level
    target_logger.setLevel(logging.DEBUG)
    try:
        assert handler in root.handlers
        target_logger.info("hi")
    finally:
        target_logger.setLevel(prior_level)
        root.removeHandler(handler)
        # Restore pre-existing handler list shape (defensive).
        assert root.handlers == pre or handler not in root.handlers

    rows = _read_events(tmp_path / "events.jsonl")
    assert any(r["payload"]["message"] == "hi" for r in rows)


def test_install_jsonl_log_handler_is_idempotent_for_same_scan_dir(tmp_path: Path) -> None:
    """Calling twice for the same scan_dir returns the same handler instance
    and does not stack two handlers on the root logger."""
    root = logging.getLogger()
    h1 = install_jsonl_log_handler(tmp_path)
    try:
        before_count = sum(1 for h in root.handlers if isinstance(h, JsonlLogHandler))
        h2 = install_jsonl_log_handler(tmp_path)
        after_count = sum(1 for h in root.handlers if isinstance(h, JsonlLogHandler))
        assert h1 is h2
        assert before_count == after_count
    finally:
        root.removeHandler(h1)


def test_install_jsonl_log_handler_adds_separate_handler_for_different_scan_dir(
    tmp_path: Path,
) -> None:
    """Two different scan dirs get two handlers (one per scan)."""
    root = logging.getLogger()
    dir_a = tmp_path / "scan_a"
    dir_b = tmp_path / "scan_b"
    h_a = install_jsonl_log_handler(dir_a)
    h_b = install_jsonl_log_handler(dir_b)
    try:
        assert h_a is not h_b
        assert h_a in root.handlers
        assert h_b in root.handlers
    finally:
        root.removeHandler(h_a)
        root.removeHandler(h_b)
