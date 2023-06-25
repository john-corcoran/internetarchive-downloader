import os
from typing import Tuple, Dict, Any
import argparse
import logging
import re
import platform

DARK_GREY = "\x1b[90;20m"
BOLD_GREY = "\x1b[37;1m"
BLUE = "\x1b[94;20m"
GREEN = "\x1b[92;20m"
YELLOW = "\x1b[33;20m"
RED = "\x1b[31;20m"
BOLD_RED = "\x1b[31;1m"
RESET = "\x1b[0m"


class MsgCounterHandler(logging.Handler):
    """Custom logging handler to count number of calls per log level"""

    def __init__(self, *args, **kwargs) -> None:
        super(MsgCounterHandler, self).__init__(*args, **kwargs)
        self.count = {}
        self.count["WARNING"] = 0
        self.count["ERROR"] = 0

    def emit(self, record) -> None:
        levelname = record.levelname
        if levelname not in self.count:
            self.count[levelname] = 0
        self.count[levelname] += 1


class TermEscapeCodeFilter:
    """A class to strip the escape codes from log messages"""
    escape_re = re.compile(r"\x1b\[[0-9;]*m")

    @classmethod
    def filter(cls, text):
        return re.sub(cls.escape_re, "", text)


class ColorFormatter(logging.Formatter):
    msg_format = "%(asctime)s - %(levelname)s - %(message)s"

    FORMATS = {
        logging.DEBUG: DARK_GREY + msg_format + RESET,
        logging.INFO: DARK_GREY + msg_format + RESET,
        logging.WARNING: YELLOW + msg_format + RESET,
        logging.ERROR: RED + msg_format + RESET,
        logging.CRITICAL: BOLD_RED + msg_format + RESET,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, "%Y-%m-%d %H:%M:%S")
        return formatter.format(record)


def prepare_logging(
    datetime_string: str, folder_path: str, identifier: str, args: Dict[str, Any]
) -> Tuple[logging.Logger, MsgCounterHandler]:
    """Prepare and return logging object to be used throughout script"""
    # INFO events and above will be written to both the console and a log file
    # DEBUG events and above will be written only to a (separate) log file
    log = logging.getLogger(__name__)
    log.setLevel(logging.DEBUG)
    # 'Quiet' logger for when quiet flag used in functions
    quiet = logging.getLogger("quiet")
    quiet.setLevel(logging.ERROR)

    log_file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    debug_log = logging.FileHandler(
        os.path.join(folder_path, f"{datetime_string}_{identifier}_debug.log")
    )
    debug_log.setLevel(logging.DEBUG)
    debug_log.setFormatter(log_file_formatter)

    info_log = logging.FileHandler(
        os.path.join(folder_path, f"{datetime_string}_{identifier}_info.log")
    )
    info_log.setLevel(logging.INFO)
    info_log.setFormatter(log_file_formatter)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(ColorFormatter())

    counter_handler = MsgCounterHandler()

    log.addHandler(debug_log)
    log.addHandler(info_log)
    log.addHandler(console_handler)
    log.addHandler(counter_handler)
    # Log platform details and commandline arguments
    platform_detail_requests = [
        "python_version",
        "system",
        "machine",
        "platform",
        "version",
        "mac_ver",
    ]
    for platform_detail_request in platform_detail_requests:
        try:
            log.debug(
                "%s: %s",
                platform_detail_request,
                getattr(platform, platform_detail_request)()
            )
        except:  # pylint: disable=W0702
            pass
    # Sanitise username and passwords if credentials flag is present
    if "credentials" in args:
        if args["credentials"] is not None:
            args["credentials"] = ["***", "***"]
    log.debug("commandline_args: %s", args)
    return log, counter_handler


def check_argument_int_greater_than_one(value: str) -> int:
    """Confirm numeric values provided as command line arguments are >= 1"""
    ivalue = int(value)
    if ivalue <= 0:
        raise argparse.ArgumentTypeError(f"{value} is an invalid positive int value")
    return ivalue
