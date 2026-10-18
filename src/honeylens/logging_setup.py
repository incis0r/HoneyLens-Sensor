"""One logging configuration per process: consistent format, optional file.

Usage::

    from honeylens.logging_setup import setup_logging
    setup_logging()                                    # console only
    setup_logging(log_file=Path("/var/log/honeylens/api.log"))
    setup_logging(level="DEBUG")
"""

import logging
import sys
from pathlib import Path

_LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_configured = False


def setup_logging(
    level: str = "INFO", log_file: Path | str | None = None, log_format: str | None = None
) -> None:
    """Configure the root logger. Subsequent calls change nothing.

    The console (stderr) gets INFO and above, the file everything from DEBUG. An
    unavailable log file is a warning, not a startup failure: a sensor without a log file
    is better than a sensor that did not come up.
    """
    global _configured
    if _configured:
        return

    fmt = logging.Formatter(log_format or _LOG_FORMAT)
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.INFO)
    console.setFormatter(fmt)
    root.addHandler(console)

    if log_file:
        path = Path(log_file)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(path)
        except OSError as exc:
            root.warning("Could not create log file %s: %s", path, exc)
        else:
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(fmt)
            root.addHandler(file_handler)

    _configured = True
