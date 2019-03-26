import sys
import logging
import logging.handlers

__author__ = 'ft'


def get_logger(progname: str, debug: bool, syslog: bool) -> logging.Logger:
    """Initialize a logger."""
    level = logging.INFO if not debug else logging.DEBUG
    logging.basicConfig(level=level, stream=sys.stderr,
                        format='%(asctime)s: %(name)s: %(levelname)s %(message)s')
    logger = logging.getLogger(progname)
    # If stderr is not a TTY, change the log level of the StreamHandler (stream = sys.stderr above) to WARNING
    if not sys.stderr.isatty() and not debug:
        for this_h in logging.getLogger('').handlers:
            this_h.setLevel(logging.WARNING)
    if syslog:
        syslog_h = logging.handlers.SysLogHandler()
        formatter = logging.Formatter('%(name)s: %(levelname)s %(message)s')
        syslog_h.setFormatter(formatter)
        logger.addHandler(syslog_h)
    return logger
