"""Logging initialisation code."""

import logging
import logging.handlers
import os
import sys
import time

__author__ = "ft"

FILE_FORMATTER = "%(asctime)s: %(name)s: %(levelname)s %(message)s"
SYSLOG_FORMATTER = "%(name)s: %(levelname)s %(message)s"


def get_logger(
    progname: str, debug: bool = False, syslog: bool = False, filelog: bool = False
) -> logging.Logger:
    """Initialize a logger."""
    level = logging.INFO if not debug else logging.DEBUG
    logging.basicConfig(level=level, stream=sys.stderr, format=FILE_FORMATTER)
    logger = logging.getLogger()
    # If stderr is not a TTY, change the log level of the StreamHandler (stream = sys.stderr above) to WARNING
    if not sys.stderr.isatty() and not debug:
        for this_h in logging.getLogger("").handlers:
            this_h.setLevel(logging.WARNING)
    if syslog:
        syslog_f = logging.Formatter(SYSLOG_FORMATTER)
        syslog_h = logging.handlers.SysLogHandler()
        syslog_h.setFormatter(syslog_f)
        logger.addHandler(syslog_h)
    if filelog:
        file_f = logging.Formatter(FILE_FORMATTER)
        file_h = logging.FileHandler(
            f"{progname}-{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}.log"
        )
        file_h.setFormatter(file_f)
        logger.addHandler(file_h)
    return logger
