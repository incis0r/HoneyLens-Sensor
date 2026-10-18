"""core.logging_setup — one root-logger configuration per process."""

from __future__ import annotations

import logging
from pathlib import Path

from honeylens import logging_setup


def _reset_root() -> None:
    """Remove only the handlers installed by setup_logging; the caplog handler (a
    StreamHandler subclass) must stay, otherwise the test sees nothing."""
    root = logging.getLogger()
    for h in list(root.handlers):
        if type(h) in (logging.StreamHandler, logging.FileHandler):
            root.removeHandler(h)
    logging_setup._configured = False


def test_configures_once_with_console_and_file(tmp_path: Path) -> None:
    _reset_root()
    log = tmp_path / "sub" / "sensor.log"
    try:
        logging_setup.setup_logging(level="debug", log_file=log)
        root = logging.getLogger()
        assert root.level == logging.DEBUG
        kinds = {type(h) for h in root.handlers}
        assert logging.StreamHandler in kinds and logging.FileHandler in kinds
        n = len(root.handlers)
        logging_setup.setup_logging()  # second call: adds nothing
        assert len(root.handlers) == n
        logging.getLogger("t").warning("hello file")
        for h in root.handlers:
            h.flush()
        assert "hello file" in log.read_text()
    finally:
        _reset_root()


def test_unwritable_log_file_is_reported_not_fatal(tmp_path: Path, caplog) -> None:
    _reset_root()
    blocker = tmp_path / "file"
    blocker.write_text("x")
    try:
        with caplog.at_level(logging.WARNING):
            logging_setup.setup_logging(log_file=blocker / "impossible.log")
        assert any("Could not create log file" in r.message for r in caplog.records)
    finally:
        _reset_root()
