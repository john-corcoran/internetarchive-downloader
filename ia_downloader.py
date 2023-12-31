#!/usr/bin/env python3

"""Script to perform simultaneous, resumable and hash-verified downloads from Internet Archive"""

import argparse
from dataclasses import dataclass, field
import datetime
import hashlib
import io
import logging
import multiprocessing
import multiprocessing.pool
import os
import pathlib
import platform
import re
import signal
import sys
import time
import typing

dark_grey = "\x1b[90;20m"
bold_grey = "\x1b[37;1m"
blue = "\x1b[94;20m"
green = "\x1b[92;20m"
yellow = "\x1b[33;20m"
red = "\x1b[31;20m"
bold_red = "\x1b[31;1m"
reset = "\x1b[0m"

python_major, python_minor = platform.python_version_tuple()[0:2]
if int(python_major) < 3 or int(python_minor) < 7:
    print(
        "Please use Python 3.7 or above (version currently installed is {})".format(
            platform.python_version()
        )
    )
    sys.exit()

try:
    import internetarchive
    import requests
    import tqdm
except ModuleNotFoundError:
    print(
        "Error loading Internet Archive module or dependencies - ensure that the Internet Archive"
        " Python Library has been installed:"
        " https://archive.org/services/docs/api/internetarchive/installation.html"
    )
    sys.exit()


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


class ColorFormatter(logging.Formatter):
    msg_format = "%(asctime)s - %(levelname)s - %(message)s"

    FORMATS = {
        logging.DEBUG: dark_grey + msg_format + reset,
        logging.INFO: dark_grey + msg_format + reset,
        logging.WARNING: yellow + msg_format + reset,
        logging.ERROR: red + msg_format + reset,
        logging.CRITICAL: bold_red + msg_format + reset,
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, "%Y-%m-%d %H:%M:%S")
        return formatter.format(record)


class TermEscapeCodeFilter(logging.Filter):
    """A class to strip the escape codes from log messages destined for log files"""

    def filter(self, record):
        escape_re = re.compile(r"\x1b\[[0-9;]*m")
        record.msg_without_colours = re.sub(escape_re, "", str(record.getMessage()))
        return True


def prepare_logging(
    datetime_string: str, folder_path: str, identifier: str, args: typing.Dict[str, typing.Any]
) -> typing.Tuple[logging.Logger, MsgCounterHandler]:
    """Prepare and return logging object to be used throughout script"""
    # INFO events and above will be written to both the console and a log file
    # DEBUG events and above will be written only to a (separate) log file
    log = logging.getLogger(__name__)
    log.setLevel(logging.DEBUG)
    # 'Quiet' logger for when quiet flag used in functions
    quiet = logging.getLogger("quiet")
    quiet.setLevel(logging.ERROR)
    log_file_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(msg_without_colours)s")
    log_file_filter = TermEscapeCodeFilter()
    debug_log = logging.FileHandler(
        os.path.join(folder_path, "{}_{}_debug.log".format(datetime_string, identifier))
    )
    debug_log.setLevel(logging.DEBUG)
    debug_log.setFormatter(log_file_formatter)
    debug_log.addFilter(log_file_filter)
    info_log = logging.FileHandler(
        os.path.join(folder_path, "{}_{}_info.log".format(datetime_string, identifier))
    )
    info_log.setLevel(logging.INFO)
    info_log.setFormatter(log_file_formatter)
    info_log.addFilter(log_file_filter)
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
                "%s: %s", platform_detail_request, getattr(platform, platform_detail_request)()
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
        raise argparse.ArgumentTypeError("{} is an invalid positive int value".format(value))
    return ivalue


def bytes_filesize_to_readable_str(bytes_filesize: int) -> str:
    """Convert bytes integer to kilobyte/megabyte/gigabyte/terabyte equivalent string"""
    if bytes_filesize < 1024:
        return "{} B"
    num = float(bytes_filesize)
    for unit in ["B", "KB", "MB", "GB"]:
        if abs(num) < 1024.0:
            return "{:.1f} {}".format(num, unit)
        num /= 1024.0
    return "{:.1f} {}".format(num, "TB")


def file_paths_in_folder(folder_path: str) -> typing.List[str]:
    """Return sorted list of paths of files at a directory (and its subdirectories)"""
    log = logging.getLogger(__name__)

    def walk_error(os_error: OSError) -> None:
        """Log any errors occurring during os.walk"""
        log.warning(
            (
                "'%s' could not be accessed during folder scanning - any contents will not be"
                " processed. Try running script as admin"
            ),
            os_error.filename,
        )

    file_paths = []
    for root, _, file_names in os.walk(folder_path, onerror=walk_error):
        for name in file_names:
            file_paths.append(os.path.join(root, name))
    return sorted(file_paths)


def get_metadata_from_hashfile(
    hash_file_path: str,
    hash_flag: bool,
    identifier_filter: typing.Optional[typing.List[str]] = None,
    file_filters: typing.Optional[typing.List[str]] = None,
    invert_file_filtering: bool = False,
) -> typing.Dict[str, str]:
    """Return dict of file paths and associated metadata parsed from IA hash metadata CSV"""
    results = {}  # type: typing.Dict[str, str]
    with open(hash_file_path, "r", encoding="utf-8") as file_handler:
        for line in file_handler:
            identifier, file_path, size, md5, _ = line.strip().split("|")
            if file_filters is not None:
                if not invert_file_filtering:
                    if not any(
                        substring.lower() in file_path.lower() for substring in file_filters
                    ):
                        continue
                else:
                    if any(substring.lower() in file_path.lower() for substring in file_filters):
                        continue
            if identifier_filter is None or identifier in identifier_filter:
                if hash_flag:
                    results[
                        os.path.join(identifier, os.path.normpath(file_path))
                    ] = md5.lower().strip()
                else:
                    results[
                        os.path.join(identifier, os.path.normpath(file_path))
                    ] = size.lower().strip()
    return results


def get_metadata_from_files_in_folder(
    folder_path: str,
    hash_flag: bool,
    relative_paths_from_ia_metadata: typing.Optional[typing.List[str]] = None,
) -> typing.Dict[str, str]:
    """Return dict of file paths and metadata of files at a directory (and its subdirectories)"""
    log = logging.getLogger(__name__)
    results = {}  # type: typing.Dict[str, str]
    if relative_paths_from_ia_metadata is not None:
        file_paths = [
            os.path.join(folder_path, relative_path)
            for relative_path in relative_paths_from_ia_metadata
        ]
    else:
        file_paths = file_paths_in_folder(folder_path)
    if hash_flag:
        for file_path in tqdm.tqdm(file_paths):
            if os.path.isfile(file_path):  # We will alert on this elsewhere if the file isn't found
                try:
                    md5 = md5_hash_file(file_path)
                    results[
                        os.path.normpath(os.path.relpath(file_path, folder_path))
                    ] = md5.lower().strip()
                except (PermissionError, OSError):
                    log.warning(
                        (
                            "PermissionError/OSError occurred when accessing file '%s' - try"
                            " running script as admin"
                        ),
                        file_path,
                    )
    else:
        # Return file sizes if we're not checking hash values
        for file_path in file_paths:
            if os.path.isfile(file_path):  # We will alert on this elsewhere if the file isn't found
                try:
                    file_size = os.path.getsize(file_path)
                    results[os.path.normpath(os.path.relpath(file_path, folder_path))] = str(
                        file_size
                    )
                except (PermissionError, OSError):
                    log.warning(
                        (
                            "PermissionError/OSError occurred when accessing file '%s' - try"
                            " running script as admin"
                        ),
                        file_path,
                    )
    return results


def md5_hash_file(filepath: str) -> str:
    """Return str containing lowercase MD5 hash value of file at a file path"""
    block_size = 64 * 1024
    md5 = hashlib.md5()
    with open(filepath, "rb") as file_handler:
        while True:
            data = file_handler.read(block_size)
            if not data:
                break
            md5.update(data)
    return md5.hexdigest()


def get_safe_path_name(path_name: str) -> str:
    """Return the provided file_name string with all non alphanumeric characters removed"""

    def safe_char(char):
        if char in {"*", '"', "/", "\\", ":", "|", "?"}:
            return "_"
        else:
            return char

    return "".join(safe_char(char) for char in path_name).rstrip("_")


def hash_pool_initializer() -> None:
    """Ignore CTRL+C in the hash worker processes (workers are daemonic so will close when the
    main process terminates)

    """
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def check_hash(file_path: str, md5_value_from_ia: str) -> typing.Tuple[str, str]:
    """Called as a separate process from the file_download function; returns results from an MD5
    hash check of a file

    """
    try:
        md5_value_local = md5_hash_file(file_path)
    except FileNotFoundError:
        return (
            "warning",
            "'{}' file seems to have been deleted before hashing could complete".format(
                os.path.basename(file_path)
            ),
        )
    except (PermissionError, OSError):
        return (
            "warning",
            "PermissionError/OSError when attempting to hash '{}'".format(
                os.path.basename(file_path)
            ),
        )
    if md5_value_local.lower().strip() == md5_value_from_ia.lower().strip():
        return (
            "debug",
            "'{}' file hash ('{}') matches between local file and IA metadata".format(
                os.path.basename(file_path), md5_value_local
            ),
        )
    return (
        "warning",
        "'{}' file hash does not match between local file ({}) and IA metadata ({})".format(
            os.path.basename(file_path), md5_value_local, md5_value_from_ia
        ),
    )


def log_update_callback(result: typing.List[typing.Tuple[str, str]]) -> None:
    """Function invoked when a hash operation completes; takes result of check_hash and adds to
    log

    """
    log = logging.getLogger(__name__)
    log_level, log_message = result[0]
    getattr(log, log_level)(log_message)


def does_file_have_416_issue(file_path: str) -> bool:
    """Check to see if a file has an embedded '416 status' error in its tail

    Internet Archive servers can sometimes suddenly throw a 416 status ("Requested Range Not
    Satisfiable") on resumable / split downloads. When this occurs, sometimes the partially
    downloaded file will have content in its tail similar to:
      <html><head><title>416 Requested Range Not Satisfiable</title></head>
      <body><center><h1>416 Requested Range Not Satisfiable</h1></center>
      <hr><center>nginx/1.18.0 (Ubuntu)</center></body></html>
    In testing, can't just remove this tail and resume the download, as when diffing a completed
    verified file against a partially downloaded '416' file, the file data deviates not at the tail
    but much earlier in the file. So, this function checks to see if this issue has occurred, to
    make a decision during download of whether the partially downloaded file needs to be removed
    and started again
    """
    with open(file_path, "rb") as file_handler:
        file_handler.seek(-1024, os.SEEK_END)
        if b"416 Requested Range Not Satisfiable" in file_handler.read():
            return True
    return False


def file_download(
    download_details: typing.Tuple[
        str,
        str,
        int,
        str,
        int,
        str,
        typing.Optional[multiprocessing.pool.Pool],
        bool,
        int,
        typing.Optional[typing.Tuple[int, int]],
        typing.Optional[int],
    ]
) -> None:
    """Called as separate threads from the download function; takes one of the files to be
    downloaded from the download_queue and downloads, with subsequent (optional) MD5 hash
    verification

    """
    log = logging.getLogger(__name__)
    (
        identifier,
        ia_file_name,
        ia_file_size,
        ia_md5,
        ia_mtime,
        output_folder,
        hash_pool,
        resume_flag,
        split_count,
        bytes_range,
        chunk_number,
    ) = download_details
    start_time = datetime.datetime.now()
    file_size_split_limit = 10485760  # 10MB
    dest_file_path = os.path.join(os.path.join(output_folder, identifier), ia_file_name)
    dest_file_name = ia_file_name
    expected_file_size = ia_file_size
    # If our thread is part of a file split, update expectations on file paths/names and sizes
    if bytes_range is not None and chunk_number is not None:
        dest_file_path += ".{}".format(chunk_number)
        dest_file_name = os.path.basename(dest_file_path)
        expected_file_size = bytes_range[1] - bytes_range[0] + 1

    # If the destination file path exists already (i.e. file has already been (at least partially)
    # downloaded), but the file size doesn't match expectations (i.e. download was incomplete),
    # either re-download from scratch or attempt resume, depending on resume_flag argument
    initial_file_size = 0
    if os.path.isfile(dest_file_path):
        if ia_file_size != -1:  # -1 denotes that IA metadata does not contain size info
            initial_file_size = os.path.getsize(dest_file_path)
            if initial_file_size == expected_file_size:
                log.debug(
                    (
                        "'%s' - will be skipped as file with expected file size already present at"
                        " '%s'"
                    ),
                    dest_file_name,
                    dest_file_path,
                )
                return
            else:
                if initial_file_size < expected_file_size:
                    if resume_flag:
                        log.info(
                            (
                                "'%s' - exists as downloaded file '%s' but file size indicates"
                                " download was not completed; will be resumed (%.1f%% remaining)"
                            ),
                            dest_file_name,
                            dest_file_path,
                            (1 - (initial_file_size / expected_file_size)) * 100,
                        )

                    else:
                        log.info(
                            (
                                "'%s' - exists as downloaded file '%s' but file size indicates"
                                " download was not completed; will be redownloaded"
                            ),
                            dest_file_name,
                            dest_file_path,
                        )

                else:
                    log.warning(
                        (
                            "'%s' - exists as downloaded file '%s', but with a larger file size"
                            " than expected - was the file modified (either locally or on Internet"
                            " Archive) since it was downloaded?"
                        ),
                        dest_file_name,
                        dest_file_path,
                    )
                    return
        else:
            log.info(
                (
                    "'%s' - exists as downloaded file '%s' but file size metadata unavailable from"
                    " IA to confirm whether file size is as expected; will be redownloaded"
                ),
                dest_file_name,
                dest_file_path,
            )

    # If this thread is expected to create new threads for split file downloading, first need to
    # check that the web server returns a 206 status code with a 'Range' request, indicating the
    # requested can be split
    if split_count > 1 and ia_file_size > file_size_split_limit:
        response_list = internetarchive.download(
            identifier,
            files=[ia_file_name],  # type: ignore
            destdir=output_folder,
            on_the_fly=True,
            return_responses=True,
        )
        if isinstance(response_list[0], requests.Response):
            thread_test_response = response_list[0]  # type: requests.Response
            thread_test_request = thread_test_response.request  # type: requests.PreparedRequest
            headers = thread_test_request.headers
            # We're just testing this connection, so don't need the whole byte range
            headers["Range"] = "bytes={}-{}".format(0, 10)

            if thread_test_request.url is not None:
                new_response = requests.get(
                    thread_test_request.url, headers=headers, timeout=12, stream=True
                )

                if new_response.status_code == 206:
                    log.debug(
                        (
                            "'%s' - returns a 206 status when requesting a Range - can therefore"
                            " split download"
                        ),
                        ia_file_name,
                    )
                elif new_response.status_code == 200:
                    log.debug(
                        (
                            "'%s' - returns a 200 status when requesting a Range - download will"
                            " not be split"
                        ),
                        ia_file_name,
                    )
                    split_count = 1
                else:
                    log.info(
                        (
                            "'%s' - unexpected status code %s returned when testing file splitting"
                            " - download will be attempted without splitting"
                        ),
                        ia_file_name,
                        new_response.status_code,
                    )
                    split_count = 1
            else:
                log.info(
                    "Unexpected response data returned from internetarchive package; download will"
                    " not be split"
                )
                split_count = 1
        else:
            log.info(
                "Unexpected response data returned from internetarchive package; download will not"
                " be split"
            )
            split_count = 1

    # Perform file download splitting
    if split_count > 1 and ia_file_size > file_size_split_limit:
        download_queue = []
        chunk_sizes = {}

        # Create byte ranges that will be used in each chunk thread, and create the download_queue
        # the thread pool will take download from
        for chunk_counter in range(split_count):
            if chunk_counter == 0:
                lower_bytes_range = 0
            else:
                lower_bytes_range = ((ia_file_size // split_count) * chunk_counter) + 1
            if chunk_counter == split_count - 1:  # For the last chunk, make sure we get everything
                upper_bytes_range = ia_file_size - 1
            else:
                upper_bytes_range = (ia_file_size // split_count) * (chunk_counter + 1)

            download_queue.append(
                (
                    identifier,
                    ia_file_name,
                    ia_file_size,
                    ia_md5,
                    ia_mtime,
                    output_folder,
                    hash_pool,
                    resume_flag,
                    1,  # split_count
                    (lower_bytes_range, upper_bytes_range),
                    chunk_counter,
                )
            )
            chunk_sizes[chunk_counter] = upper_bytes_range - lower_bytes_range + 1

        with multiprocessing.pool.ThreadPool(split_count) as download_pool:
            # Chunksize 1 used to ensure downloads occur in filename order
            log.info("'%s' - will be downloaded in %s parts", ia_file_name, split_count)
            download_pool.map(file_download, download_queue, chunksize=1)
            download_pool.close()
            download_pool.join()

        # When file chunk downloads have finished in above thread pool, check the chunks are the
        # expected size
        failed_indicator = False
        for chunk_counter in range(split_count):
            chunk_file_path = "{}.{}".format(dest_file_path, chunk_counter)

            if not os.path.isfile(chunk_file_path):
                log.warning(
                    "'%s' - chunk %s (sub-file '%s') cannot be found",
                    ia_file_name,
                    chunk_counter,
                    chunk_file_path,
                )
                failed_indicator = True
            elif os.path.getsize(chunk_file_path) != chunk_sizes[chunk_counter]:
                log.warning(
                    (
                        "'%s' - chunk %s (sub-file '%s') is not the expected size (expected size"
                        " %s, actual size %s)"
                    ),
                    ia_file_name,
                    chunk_counter,
                    chunk_file_path,
                    chunk_sizes[chunk_counter],
                    os.path.getsize(chunk_file_path),
                )
                failed_indicator = True

        if failed_indicator:
            log.warning(
                (
                    "'%s' - error occurred with file chunks - file could not be reconstructed"
                    " and has therefore not been downloaded successfully"
                ),
                ia_file_name,
            )
        else:
            # Merge the chunks into the final file and delete each chunk as we go
            block_size = 4096 * 1024
            with open(dest_file_path, "wb") as output_file_handler:
                for chunk_counter in range(split_count):
                    chunk_file_path = "{}.{}".format(dest_file_path, chunk_counter)
                    with open(chunk_file_path, "rb") as input_file_handler:
                        while True:
                            data = input_file_handler.read(block_size)
                            if not data:
                                break
                            output_file_handler.write(data)
                    os.remove(chunk_file_path)
    else:
        # In testing, downloads can timeout occasionally with requests.exceptions.ConnectionError
        # raised; catch and attempt download five times before giving up
        connection_retry_counter = 0
        size_retry_counter = 0
        MAX_RETRIES = 5
        connection_wait_timer = 600
        size_wait_timer = 600
        while True:
            try:
                if not resume_flag and chunk_number is None:
                    log.info("%s'%s'%s - beginning download", bold_grey, dest_file_name, blue)
                    while True:
                        try:
                            internetarchive.download(
                                identifier,
                                files=[ia_file_name],  # type: ignore
                                destdir=output_folder,
                                on_the_fly=True,
                            )
                            break
                        except requests.exceptions.HTTPError as http_error:
                            status_code = http_error.response.status_code
                            if status_code == 403:
                                log.warning(
                                    (
                                        "'%s' - 403 Forbidden error occurred - an account login may"
                                        " be required to access this file (account details can be"
                                        " passed using the '-c' flag) - note that download may not"
                                        " be possible even when logged in, if the file is within a"
                                        " restricted access item (e.g. books in the lending program"
                                        " or 'stream only' videos)"
                                    ),
                                    ia_file_name,
                                )
                            else:
                                log.warning(
                                    "'%s' - %s error status returned when attempting download",
                                    ia_file_name,
                                    status_code,
                                )
                            return
                        except FileExistsError:
                            log.debug(
                                (
                                    "FileExistsError for '%s' occurred - this seems to happen"
                                    " occasionally on Windows and Ubuntu, but a retry seems to fix"
                                ),
                                ia_file_name,
                            )
                            time.sleep(2)
                else:
                    partial_file_size = 0
                    if os.path.isfile(dest_file_path):
                        if ia_file_size == -1 or not resume_flag:
                            # If we don't have size metadata from IA (i.e. if file_size == -1), then
                            # perform a full re-download. (Although we could run a hash check
                            # instead, in testing it seems that any IA file that lacks size metadata
                            # will also give different hash values per download - so would be
                            # wasting time to calc hash as there'll always be a mismatch requiring
                            # a full re-download)
                            log.info(
                                "%s'%s'%s - beginning re-download", bold_grey, dest_file_name, blue
                            )
                            file_write_mode = "wb"
                        elif resume_flag:
                            log.info(
                                "%s'%s'%s - resuming download", bold_grey, dest_file_name, blue
                            )
                            file_write_mode = "ab"
                            partial_file_size = os.path.getsize(dest_file_path)
                    else:
                        log.info("%s'%s'%s - beginning download", bold_grey, dest_file_name, blue)
                        file_write_mode = "wb"
                        pathlib.Path(os.path.dirname(dest_file_path)).mkdir(
                            parents=True, exist_ok=True
                        )

                    # If we're wanting to be able to resume file transfers, we will use the
                    # internetarchive.download function to just return the PreparedResponse object
                    # with which we can make a new Request
                    # (We are doing this as internetarchive.download will otherwise delete a
                    # partially-downloaded file if a ConnectionError occurs, meaning we would have
                    # nothing left to try and resume)
                    try:
                        response_list = internetarchive.download(
                            identifier,
                            files=[ia_file_name],  # type: ignore
                            destdir=output_folder,
                            on_the_fly=True,
                            return_responses=True,
                        )
                    except requests.exceptions.HTTPError as http_error:
                        status_code = http_error.response.status_code
                        if status_code == 403:
                            log.warning(
                                (
                                    "'%s' - 403 Forbidden error occurred - an account login may be"
                                    " required to access this file (account details can be passed"
                                    " using the '-c' flag) - note that download may not be possible"
                                    " even when logged in, if the file is within a restricted"
                                    " access item (e.g. books in the lending program)"
                                ),
                                ia_file_name,
                            )
                        else:
                            log.warning(
                                "'%s' - %s error status returned", ia_file_name, status_code
                            )
                        return
                    if not isinstance(response_list[0], requests.Response):
                        raise ConnectionError(response_list[0])  # This should be an error message
                    response = response_list[0]  # type: requests.Response
                    request = response.request  # type: requests.PreparedRequest
                    headers = request.headers

                    updated_bytes_range = None
                    if file_write_mode == "ab":
                        # If we don't have bytes_range, this download isn't a file chunk, so just
                        # download all the remaining file data
                        if bytes_range is None:
                            updated_bytes_range = (partial_file_size, ia_file_size - 1)
                        # Otherwise, this is a file chunk, so only download up to the final amount
                        # needed for this chunk
                        else:
                            lower_bytes_range = bytes_range[0] + partial_file_size
                            updated_bytes_range = (lower_bytes_range, bytes_range[1])
                    elif bytes_range is not None:
                        updated_bytes_range = bytes_range

                    # Set the bytes range if we're either resuming a download or downloading a file
                    # chunk
                    if updated_bytes_range is not None:
                        headers["Range"] = "bytes={}-{}".format(
                            updated_bytes_range[0], updated_bytes_range[1]
                        )
                        log.debug(
                            "'%s' - range to be requested (being downloaded as file '%s') is %s-%s",
                            ia_file_name,
                            dest_file_name,
                            updated_bytes_range[0],
                            updated_bytes_range[1],
                        )

                    if request.url is not None:
                        new_response = requests.get(
                            request.url, headers=headers, timeout=12, stream=True
                        )
                    else:
                        log.warning(
                            "Unexpected response data returned from internetarchive package;"
                            " download not completed"
                        )
                        return

                    log.debug(
                        "'%s' - %s status for request (being downloaded as file '%s')",
                        ia_file_name,
                        new_response.status_code,
                        dest_file_name,
                    )

                    if new_response.status_code == 200 or new_response.status_code == 206:
                        file_download_write_block_size = 1000000
                        with open(dest_file_path, file_write_mode) as file_handler:
                            for download_chunk in new_response.iter_content(
                                chunk_size=file_download_write_block_size
                            ):
                                if download_chunk:
                                    file_handler.write(download_chunk)

                        try:
                            if (
                                ia_mtime != -1
                            ):  # -1 denotes that IA metadata does not contain mtime info
                                os.utime(dest_file_path, (0, ia_mtime))
                        except OSError:
                            # Probably file-like object, e.g. sys.stdout.
                            pass
                    elif new_response.status_code == 416:
                        if os.path.isfile(dest_file_path):
                            if does_file_have_416_issue(dest_file_path):
                                log.info(
                                    (
                                        "416 error message has been embedded in partially"
                                        " downloaded file '%s', causing file corruption; the"
                                        " partially downloaded file will be deleted"
                                    ),
                                    dest_file_name,
                                )
                                os.remove(dest_file_path)
                        if size_retry_counter < MAX_RETRIES:
                            log.info(
                                (
                                    "416 status returned for request for IA file '%s' (being"
                                    " downloaded as file '%s') - indicating that the IA server"
                                    " cannot proceed with resumed download at this time - waiting"
                                    " %s minutes before retrying (will retry %s more times)"
                                ),
                                ia_file_name,
                                dest_file_name,
                                int(size_wait_timer / 60),
                                MAX_RETRIES - size_retry_counter,
                            )

                            time.sleep(size_wait_timer)
                            size_retry_counter += 1
                            size_wait_timer *= (
                                2  # Add some delay for each retry in case connection issue is
                                # ongoing
                            )
                            continue
                        log.warning(
                            (
                                "Persistent 416 statuses returned for IA file '%s' (being"
                                " downloaded as file '%s') - server may be having temporary issues;"
                                " download not completed"
                            ),
                            ia_file_name,
                            dest_file_name,
                        )
                        return
                    else:
                        log.warning(
                            (
                                "Unexpected status code %s returned for IA file '%s' (being"
                                " downloaded as file '%s') - download not completed"
                            ),
                            new_response.status_code,
                            ia_file_name,
                            dest_file_name,
                        )
                        return

            except (
                requests.exceptions.ConnectionError,
                requests.exceptions.ReadTimeout,
                ConnectionError,
            ):
                if connection_retry_counter < MAX_RETRIES:
                    log.info(
                        (
                            "ConnectionError/ReadTimeout occurred for '%s', waiting %s minutes"
                            " before retrying (will retry %s more times)"
                        ),
                        dest_file_name,
                        int(connection_wait_timer / 60),
                        MAX_RETRIES - connection_retry_counter,
                    )
                    time.sleep(connection_wait_timer)
                    connection_retry_counter += 1
                    connection_wait_timer *= (
                        2  # Add some delay for each retry in case connection issue is ongoing
                    )
                else:
                    log.warning(
                        (
                            "'%s' - download timed out %s times; this file has not been downloaded"
                            " successfully"
                        ),
                        dest_file_name,
                        MAX_RETRIES,
                    )
                    return

            else:
                downloaded_file_size = os.path.getsize(dest_file_path)
                # In testing, have seen rare instances of the file not being fully downloaded
                # despite the response object not reporting any more data to write.
                # This appears associated with the server suddenly throwing a 416 status -
                # this can be seen by the partially downloaded file having a tail with content
                # content similar to:
                #   <html><head><title>416 Requested Range Not Satisfiable</title></head>
                #   <body><center><h1>416 Requested Range Not Satisfiable</h1></center>
                #   <hr><center>nginx/1.18.0 (Ubuntu)</center></body></html>
                # In testing, can't just remove this tail and resume the download, as when diffing
                # a completed verified file against a partially downloaded '416' file, the file
                # data deviates not at the tail but much earlier in the file.
                # So, let's delete the partially downloaded file in this situation and begin again
                if ia_file_size != -1 and downloaded_file_size < expected_file_size:
                    if size_retry_counter < MAX_RETRIES:
                        log.info(
                            (
                                "File '%s' download concluded but file size is not as expected"
                                " (file size is %s bytes, expected %s bytes). %s - partially"
                                " downloaded file will be deleted. Waiting %s minutes before"
                                " retrying (will retry %s more times)"
                            ),
                            dest_file_name,
                            downloaded_file_size,
                            expected_file_size,
                            "The server raised a 416 status error, causing file corruption"
                            if does_file_have_416_issue(dest_file_path)
                            else "In this situation the file is likely corrupt",
                            int(size_wait_timer / 60),
                            MAX_RETRIES - size_retry_counter,
                        )
                        os.remove(dest_file_path)
                        time.sleep(size_wait_timer)
                        size_retry_counter += 1
                        size_wait_timer *= (
                            2  # Add some delay for each retry in case connection issue is ongoing
                        )
                    else:
                        log.warning(
                            (
                                "Failed to increase downloaded file '%s' to expected file size"
                                " (final file size is %s, expected %s; this file has not been"
                                " downloaded successfully"
                            ),
                            dest_file_name,
                            downloaded_file_size,
                            expected_file_size,
                        )
                        return

                # If no further errors, break from the True loop
                else:
                    break

    complete_time = datetime.datetime.now()
    duration = complete_time - start_time
    duration_in_minutes = duration.total_seconds() / 60
    # Remove the data that was downloaded in previous sessions (initial_file_size) to get the
    # amount of data downloaded in this session, for accurate stats on how long it took to download
    downloaded_data_in_mb = ((expected_file_size - initial_file_size) / 1024) / 1024
    log.info(
        "%s'%s'%s - download completed in %s%s",
        bold_grey,
        dest_file_name,
        green,
        datetime.timedelta(seconds=round(int(duration.total_seconds()))),
        " ({:.2f}MB per minute)".format(downloaded_data_in_mb / duration_in_minutes)
        if expected_file_size > 1048576  # 1MB; seems inaccurate for files beneath this size
        else "",
    )
    # If user has opted to verify downloads, add the task to the hash_pool
    if chunk_number is None:  # Only hash if we're in a thread that isn't downloading a file chunk
        if hash_pool is not None:
            # Don't hash the [identifier]_files.xml file, as this regularly gives false
            # positives (see README Known Issues)
            if dest_file_name != "{}_files.xml".format(identifier):
                hash_pool.starmap_async(  # type: ignore
                    check_hash, iterable=[(dest_file_path, ia_md5)], callback=log_update_callback
                )


def download(
    identifier: str,
    output_folder: str,
    hash_file: typing.Optional[io.TextIOWrapper],
    thread_count: int,
    resume_flag: bool,
    verify_flag: bool,
    split_count: int,
    file_filters: typing.Optional[typing.List[str]],
    invert_file_filtering: bool,
    cache_parent_folder: str,
    cache_refresh: bool,
) -> None:
    """Download files associated with an Internet Archive identifier"""
    log = logging.getLogger(__name__)
    PROCESSES = multiprocessing.cpu_count() - 1
    MAX_RETRIES = 5

    # Create output folder if it doesn't already exist
    pathlib.Path(output_folder).mkdir(parents=True, exist_ok=True)

    log.info("'%s' contents will be downloaded to '%s'", identifier, output_folder)

    # If user has set to verify, create a new multiprocessing.Pool whose reference will be passed
    # to each download thread to allow for non-blocking hashing
    hash_pool = None
    if verify_flag:
        hash_pool = multiprocessing.Pool(PROCESSES, initializer=hash_pool_initializer)

    # See if the items exist in the cache
    cache_folder = os.path.join(cache_parent_folder, identifier)
    cached_item = None

    @dataclass
    class CacheDict:
        """Using this simply to allow for a custom attribute (item_metadata) if we use cache"""

        item_metadata: typing.Dict[str, typing.Any] = field(default_factory=dict)

    if not cache_refresh and os.path.isdir(cache_folder):
        cache_files = sorted(
            [
                f.path
                for f in os.scandir(cache_folder)
                if f.is_file() and f.name.endswith("metadata.txt")
            ]
        )
        if len(cache_files) > 0:
            cache_file = cache_files[-1]  # Get the most recent cache file
            # Get datetime from filename
            datetime_str = "_".join(os.path.basename(cache_file).split("_", 2)[:2])
            file_datetime = datetime.datetime.strptime(datetime_str, "%Y%m%d_%H%M%S")
            now_datetime = datetime.datetime.now()
            if now_datetime - datetime.timedelta(weeks=1) <= file_datetime <= now_datetime:
                log.debug(
                    "Cached data from %s will be used for item '%s'", datetime_str, identifier
                )

                cached_item = CacheDict()
                cached_item.item_metadata["files"] = []
                with open(cache_file, "r", encoding="utf-8") as file_handler:
                    try:
                        for line in file_handler:
                            _, file_path, size, md5, mtime = line.strip().split("|")
                            item_dict = {}
                            item_dict["name"] = file_path
                            item_dict["size"] = size
                            item_dict["md5"] = md5
                            item_dict["mtime"] = mtime
                            cached_item.item_metadata["files"].append(item_dict)
                    except ValueError:
                        log.info(
                            (
                                "Cache file '%s' does not match expected format - cache data will"
                                " be redownloaded"
                            ),
                            cache_file,
                        )
                        cached_item = None

    live_item = None
    if cached_item is None:
        connection_retry_counter = 0
        connection_wait_timer = 600
        while True:
            try:
                # Get Internet Archive metadata for the provided identifier
                live_item = internetarchive.get_item(identifier)
                if live_item is not None and "item_last_updated" in live_item.item_metadata:
                    item_updated_time = datetime.datetime.fromtimestamp(
                        int(live_item.item_metadata["item_last_updated"])
                    )
                    if item_updated_time > (datetime.datetime.now() - datetime.timedelta(weeks=1)):
                        log.warning(
                            (
                                "Internet Archive item '%s' was updated within the last week (last"
                                " updated on %s) - verification/corruption issues may occur if"
                                " files are being updated by the uploader. If such errors occur"
                                " when resuming a download, recommend using the '--cacherefresh'"
                                " flag"
                            ),
                            identifier,
                            item_updated_time.strftime("%Y-%m-%d %H:%M:%S"),
                        )
            except requests.exceptions.ConnectionError:
                if connection_retry_counter < MAX_RETRIES:
                    log.info(
                        (
                            "ConnectionError occurred when attempting to connect to Internet"
                            " Archive to get info for item '%s' - is internet connection active?"
                            " Waiting %s minutes before retrying (will retry %s more times)"
                        ),
                        identifier,
                        int(connection_wait_timer / 60),
                        MAX_RETRIES - connection_retry_counter,
                    )
                    time.sleep(connection_wait_timer)
                    connection_retry_counter += 1
                    connection_wait_timer *= (
                        2  # Add some delay for each retry in case connection issue is ongoing
                    )
                else:
                    log.warning(
                        (
                            "ConnectionError persisted when attempting to connect to Internet"
                            " Archive - is internet connection active? Download of item '%s' has"
                            " failed"
                        ),
                        identifier,
                    )
                    live_item = None
                    break
            # If no further errors, break from the True loop
            else:
                break

    if cached_item is None and live_item is None:
        return

    # Write metadata for files associated with IA identifier to a file, and populate
    # download_queue with this metadata
    item_file_count = 0
    item_total_size = 0
    item_filtered_files_size = 0

    item = live_item if live_item is not None else cached_item

    if item is not None and "files" in item.item_metadata:
        # Create cache folder for item if it doesn't already exist
        pathlib.Path(cache_folder).mkdir(parents=True, exist_ok=True)

        download_queue = []
        # If the 'item' is our custom CacheDict, then we built it from cache - so don't need to
        # write another metadata file
        if not isinstance(item, CacheDict):
            cache_file_handler = open(
                os.path.join(
                    cache_folder,
                    "{}_{}_metadata.txt".format(
                        datetime.datetime.now().strftime("%Y%m%d_%H%M%S"), identifier
                    ),
                ),
                "w",
                encoding="utf-8",
            )
        for file in item.item_metadata["files"]:
            item_file_count += 1
            if "size" in file:
                item_total_size += int(file["size"])
            # In testing it seems that the '[identifier]_files.xml' file will not have size
            # or mtime data; the below will set a default size/mtime of '-1' where needed
            if "size" not in file:
                file["size"] = -1
                log.debug("'%s' has no size metadata", file["name"])
            if "mtime" not in file:
                file["mtime"] = -1
                log.debug("'%s' has no mtime metadata", file["name"])
            log_write_str = "{}|{}|{}|{}|{}\n".format(
                identifier, file["name"], file["size"], file["md5"], file["mtime"]
            )
            if not isinstance(item, CacheDict):
                cache_file_handler.write(log_write_str)
            if file_filters is not None:
                if not invert_file_filtering:
                    if not any(
                        substring.lower() in file["name"].lower() for substring in file_filters
                    ):
                        continue
                else:
                    if any(substring.lower() in file["name"].lower() for substring in file_filters):
                        continue
            if file["size"] != -1:
                item_filtered_files_size += int(file["size"])
            if hash_file is not None:
                hash_file.write(log_write_str)

            download_queue.append(
                (
                    identifier,
                    file["name"],
                    int(file["size"]),
                    file["md5"],
                    int(file["mtime"]),
                    output_folder,
                    hash_pool,
                    resume_flag,
                    split_count,
                    None,  # bytes_range
                    None,  # chunk_number
                )
            )

        if not isinstance(item, CacheDict):
            cache_file_handler.close()

        # Check if the output folder already seems to have all the files we expect
        # Check if files in download queue equal files in folder
        identifier_output_folder = os.path.join(output_folder, identifier)
        if (
            os.path.isdir(identifier_output_folder)
            and len(file_paths_in_folder(identifier_output_folder)) > 0
        ):
            size_verification = verify(
                hash_file=None,
                data_folders=[output_folder],
                no_paths_flag=False,
                hash_flag=False,
                cache_parent_folder=cache_parent_folder,
                identifiers=[identifier],
                file_filters=file_filters,
                invert_file_filtering=invert_file_filtering,
                quiet=True,
            )
            if size_verification:
                log.info(
                    "'%s' appears to have been fully downloaded in folder '%s' - skipping",
                    identifier,
                    output_folder,
                )
                return

        if file_filters is not None:
            if not invert_file_filtering:
                if len(download_queue) > 0:
                    log.info(
                        (
                            "%s files (%s) match file filter(s) '%s' (case insensitive) and will be"
                            " downloaded (out of a total of %s files (%s) available)"
                        ),
                        len(download_queue),
                        bytes_filesize_to_readable_str(item_filtered_files_size),
                        " ".join(file_filters),
                        item_file_count,
                        bytes_filesize_to_readable_str(item_total_size),
                    )

                else:
                    log.info(
                        (
                            "No files match the filter(s) '%s' in item '%s' - no downloads will be"
                            " performed"
                        ),
                        " ".join(file_filters),
                        identifier,
                    )

                    return
            else:
                if len(download_queue) > 0:
                    log.info(
                        (
                            "%s files (%s) NOT matching file filter(s) '%s' (case insensitive) will"
                            " be downloaded (out of a total of %s files (%s) available)"
                        ),
                        len(download_queue),
                        bytes_filesize_to_readable_str(item_filtered_files_size),
                        " ".join(file_filters),
                        item_file_count,
                        bytes_filesize_to_readable_str(item_total_size),
                    )
                else:
                    log.info(
                        (
                            "All files are excluded by filter(s) '%s' in item '%s' - no downloads"
                            " will be performed"
                        ),
                        " ".join(file_filters),
                        identifier,
                    )
                    return
        else:
            log.info(
                "'%s' contains %s files (%s)",
                identifier,
                len(download_queue),
                bytes_filesize_to_readable_str(item_total_size),
            )

        # Running under context management here lets the user ctrl+c out and not get a
        # "ResourceWarning: unclosed running multiprocessing pool
        # <multiprocessing.pool.ThreadPool ..." error
        with multiprocessing.pool.ThreadPool(thread_count) as download_pool:
            # Chunksize 1 used to ensure downloads occur in filename order
            download_pool.map(file_download, download_queue, chunksize=1)
            log.debug("Waiting for download pool to complete")
            download_pool.close()
            download_pool.join()  # Blocks until download threads are complete

        # Do a 'basic' verification of data (just checking file sizes and paths, not hash
        # values) - this is separate to hash checks that will be performed as downloads
        # complete if the user has opted to '--verify'
        log.info("Download phase complete for item '%s'", identifier)
        # Ensure hash file is written to disk to use in verify function
        if hash_file is not None:
            hash_file.flush()
            os.fsync(hash_file.fileno())
        verify(
            hash_file=None,
            data_folders=[output_folder],
            no_paths_flag=False,
            hash_flag=False,
            cache_parent_folder=cache_parent_folder,
            identifiers=[identifier],
            file_filters=file_filters,
            invert_file_filtering=invert_file_filtering,
        )

    else:
        log.warning(
            (
                "No files found associated with Internet Archive identifier '%s' (check that"
                " the correct identifier has been entered)"
            ),
            identifier,
        )
    if hash_pool is not None:
        log.debug("Waiting for hash tasks to complete")
        hash_pool.close()
        hash_pool.join()  # Blocks until hashing processes are complete


def verify(
    hash_file: typing.Optional[str],
    data_folders: typing.List[str],
    no_paths_flag: bool,
    hash_flag: bool,
    cache_parent_folder: str,
    identifiers: typing.Optional[typing.List[str]] = None,
    file_filters: typing.Optional[typing.List[str]] = None,
    invert_file_filtering: bool = False,
    quiet: bool = False,
) -> bool:
    """Verify that previously-downloaded files are complete"""
    if quiet:
        log = logging.getLogger("quiet")
    else:
        log = logging.getLogger(__name__)
    if hash_file is not None and not os.path.isfile(hash_file):
        log.error("File '%s' does not exist", hash_file)
        return False
    for data_folder in data_folders:
        if not os.path.isdir(data_folder):
            log.error("Folder '%s' does not exist", data_folder)
            return False

    errors = 0
    for data_folder in data_folders:
        # Get comparable dictionaries from both the hash metadata file (i.e. IA-side metadata)
        # and local folder of files (i.e. local-side metadata of previously-downloaded files)
        missing_metadata_items = []
        if hash_file is not None:
            try:
                hashfile_metadata = get_metadata_from_hashfile(
                    hash_file, hash_flag, identifiers, file_filters, invert_file_filtering
                )
            except ValueError:
                log.error(
                    (
                        "Hash file '%s' does not match expected format - cannot be used for"
                        " verification"
                    ),
                    hash_file,
                )
                return False
        else:
            subfolders = [
                item
                for item in os.listdir(data_folder)
                if os.path.isdir(os.path.join(data_folder, item))
            ]
            hashfile_metadata = {}
            if len(subfolders) == 0:
                log.warning(
                    (
                        "No item folders were found in provided data folder '%s' -"
                        " make sure the parent download folder was provided rather than the"
                        " item subfolder (e.g. provide '/downloads/' rather than"
                        " '/downloads/item/'"
                    ),
                    data_folder,
                )
            for subfolder in subfolders:
                if identifiers is not None:
                    if subfolder not in identifiers:
                        continue
                # Find cache data for the subfolder (item) in question
                cache_folder = os.path.join(cache_parent_folder, subfolder)
                if os.path.isdir(cache_folder):
                    # Get most recent cache file in folder
                    cache_files = sorted(
                        [
                            f.path
                            for f in os.scandir(cache_folder)
                            if f.is_file() and f.name.endswith("metadata.txt")
                        ]
                    )
                    if len(cache_files) > 0:
                        cache_file = cache_files[-1]
                        try:
                            hashfile_metadata.update(
                                get_metadata_from_hashfile(
                                    cache_file,
                                    hash_flag,
                                    identifiers,
                                    file_filters,
                                    invert_file_filtering,
                                )
                            )
                        except ValueError:
                            log.warning(
                                (
                                    "Cache file '%s' does not match expected format - cannot be"
                                    " used for verification"
                                ),
                                cache_file,
                            )
                            missing_metadata_items.append(subfolder)
                    else:
                        log.warning(
                            (
                                "Cache data not found for subfolder/item '%s' - files for this item"
                                " will not be checked"
                            ),
                            subfolder,
                        )
                        missing_metadata_items.append(subfolder)
                else:
                    log.warning(
                        (
                            "Cache data not found for subfolder/item '%s' - files for this item"
                            " will not be checked"
                        ),
                        subfolder,
                    )
                    missing_metadata_items.append(subfolder)

        if len(hashfile_metadata) == 0:
            log.error(
                "Hash file '{}' is empty - check correct file has been provided".format(hash_file)
                if hash_file is not None
                else "No metadata found in cache - verification cannot be performed"
            )
            errors += 1
            continue

        relative_paths_from_ia_metadata = list(hashfile_metadata.keys())

        if hash_flag:
            md5_or_size_str = "MD5"
        else:
            md5_or_size_str = "Size"

        if identifiers is None:
            log.info(
                "Verification of %s metadata for files in folder '%s' begun%s",
                md5_or_size_str,
                data_folder,
                " (using hash file '{}')".format(hash_file) if hash_file is not None else "",
            )

        else:
            log.info(
                "Verification of %s metadata for item(s) %s files in folder '%s' begun",
                md5_or_size_str,
                ", ".join(["'{}'".format(identifier) for identifier in identifiers]),
                data_folder,
            )

        mismatch_count = 0
        if no_paths_flag:
            folder_metadata = get_metadata_from_files_in_folder(data_folder, hash_flag)
        else:
            unique_identifier_dirs_from_ia_metadata = sorted(
                list(
                    set(
                        [
                            pathlib.Path(relative_path).parts[0]
                            for relative_path in relative_paths_from_ia_metadata
                        ]
                    )
                )
            )
            # Print warnings for item folders referenced in IA metadata that aren't found in
            # the provided data folder
            nonexistent_dirs = []
            for identifier_dir in unique_identifier_dirs_from_ia_metadata:
                if not os.path.isdir(os.path.join(data_folder, identifier_dir)):
                    log.warning(
                        (
                            "Expected item folder '%s' was not found in provided data folder '%s' -"
                            " make sure the parent download folder was provided rather than the"
                            " item subfolder (e.g. provide '/downloads/' rather than"
                            " '/downloads/item/'"
                        ),
                        identifier_dir,
                        data_folder,
                    )
                    nonexistent_dirs.append(identifier_dir)

            folder_metadata = get_metadata_from_files_in_folder(
                data_folder, hash_flag, relative_paths_from_ia_metadata
            )

            # Group warnings for each file in a non-existent folder into one unified warning
            for nonexistent_dir in nonexistent_dirs:
                nonexistent_files = [
                    relative_path
                    for relative_path in relative_paths_from_ia_metadata
                    if pathlib.Path(relative_path).parts[0] == nonexistent_dir
                ]
                log.warning(
                    "Files in non-existent folder '%s' not found: %s",
                    nonexistent_dir,
                    ", ".join(
                        ["'{}'".format(nonexistent_file) for nonexistent_file in nonexistent_files]
                    ),
                )

                mismatch_count += len(nonexistent_files)
                # Delete non-existent files from the hashfile_metadata so we don't end up
                # iterating these later and printing more warning messages than necessary
                for nonexistent_file in nonexistent_files:
                    if nonexistent_file in hashfile_metadata:
                        del hashfile_metadata[nonexistent_file]

        # Don't consider the [identifier]_files.xml files, as these regularly gives false
        # positives (see README Known Issues)
        xml_files_to_be_removed = [
            relative_path
            for relative_path in relative_paths_from_ia_metadata
            if os.path.basename(relative_path)
            == "{}_files.xml".format(pathlib.Path(relative_path).parts[0])
        ]
        for xml_file_to_be_removed in xml_files_to_be_removed:
            if xml_file_to_be_removed in hashfile_metadata:
                del hashfile_metadata[xml_file_to_be_removed]

        # If user has moved files, so they're no longer in the same relative file paths, they
        # will need to set the 'nopaths' flag so that only hash/size metadata is checked rather
        # than path data as well
        # Disadvantage of this approach is that, if a file is stored in multiple locations, the
        # unique hash/size will only be checked for once - so any deletions of multiple copies
        # of the file will not be flagged
        if no_paths_flag:
            # Iterate only for hashes/sizes in the IA metadata that are not present in the local
            # folder of downloaded files
            for value in [
                value
                for value in hashfile_metadata.values()
                if value not in folder_metadata.values()
            ]:
                log.warning(
                    "%s '%s' (original filename(s) '%s') not found in data folder",
                    md5_or_size_str,
                    value,
                    [k for k, v in hashfile_metadata.items() if v == value],
                )
                mismatch_count += 1

        else:
            for file_path, value in hashfile_metadata.items():
                if file_path not in folder_metadata:
                    log.warning("File '%s' not found in data folder '%s'", file_path, data_folder)
                    mismatch_count += 1
                else:
                    if value != folder_metadata[file_path]:
                        if value != "-1":
                            log.warning(
                                (
                                    "File '%s' %s does not match ('%s' in IA metadata, '%s' in data"
                                    " folder)"
                                ),
                                file_path,
                                md5_or_size_str,
                                value,
                                folder_metadata[file_path],
                            )

                            mismatch_count += 1
                        else:
                            log.debug(
                                (
                                    "File '%s' %s is not available in IA metadata, so verification"
                                    " not performed on this file"
                                ),
                                file_path,
                                md5_or_size_str,
                            )

        issue_message = ""
        if len(missing_metadata_items) > 0:
            issue_message += "cached metadata missing for items {}; ".format(
                ", ".join(["'{}'".format(item) for item in missing_metadata_items])
            )
        if mismatch_count > 0:
            issue_message += (
                "{} files were not present or did not match Internet Archive {} metadata; ".format(
                    mismatch_count, md5_or_size_str
                )
            )
        if issue_message == "":
            issue_message = (
                "all files were verified against Internet Archive {} data with no issues identified"
                .format(md5_or_size_str)
            )
        else:
            issue_message = issue_message[:-2]
        if identifiers is None:
            log.info("Verification of folder '%s' complete: %s", data_folder, issue_message)
        else:
            log.info(
                "Verification of item(s) %s in folder '%s' complete: %s",
                ", ".join(["'{}'".format(identifier) for identifier in identifiers]),
                data_folder,
                issue_message,
            )
        errors += len(missing_metadata_items) + mismatch_count
    if errors > 0:
        return False
    return True


def get_identifiers_from_search_term(
    search: str, cache_parent_folder: str, cache_refresh: bool
) -> typing.List[str]:
    log = logging.getLogger(__name__)
    MAX_RETRIES = 5
    identifiers = []
    # See if the search exists in the cache
    cache_folder = os.path.join(cache_parent_folder, f"search-{get_safe_path_name(search)}")
    if not cache_refresh and os.path.isdir(cache_folder):
        cache_files = sorted(
            [
                f.path
                for f in os.scandir(cache_folder)
                if f.is_file() and f.name.endswith("items.txt")
            ]
        )
        if len(cache_files) > 0:
            cache_file = cache_files[-1]
            # Get datetime from filename
            datetime_str = "_".join(os.path.basename(cache_file).split("_", 2)[:2])
            file_datetime = datetime.datetime.strptime(datetime_str, "%Y%m%d_%H%M%S")
            now_datetime = datetime.datetime.now()
            if now_datetime - datetime.timedelta(weeks=1) <= file_datetime <= now_datetime:
                log.debug(
                    "Cached data from %s will be used for search term '%s'", datetime_str, search
                )

                with open(cache_file, "r", encoding="utf-8") as file_handler:
                    for line in file_handler:
                        identifiers.append(line.strip())
    if len(identifiers) == 0:
        connection_retry_counter = 0
        connection_wait_timer = 600
        while True:
            try:
                search_results = internetarchive.search_items(
                    search, fields=["identifier"], max_retries=3
                )
                for search_result in search_results:
                    identifiers.append(search_result["identifier"])
                if len(identifiers) > 0:
                    log.info(
                        (
                            "Internet Archive search term '%s' contains %s individual Internet"
                            " Archive items; each will be downloaded"
                        ),
                        search,
                        len(identifiers),
                    )
                    # Create cache folder for search if it doesn't already exist
                    pathlib.Path(cache_folder).mkdir(parents=True, exist_ok=True)

                    # Write search's identifiers to metadata file
                    with open(
                        os.path.join(
                            cache_folder,
                            "{}_{}_items.txt".format(
                                datetime.datetime.now().strftime("%Y%m%d_%H%M%S"),
                                get_safe_path_name(search),
                            ),
                        ),
                        "w",
                        encoding="utf-8",
                    ) as file_handler:
                        for identifier in identifiers:
                            file_handler.write("{}\n".format(identifier))
                else:
                    log.warning(
                        (
                            "No items associated with search term '%s' were identified - was the"
                            " search term entered correctly?"
                        ),
                        search,
                    )
                    return []
            except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout):
                if connection_retry_counter < MAX_RETRIES:
                    log.info(
                        (
                            "Connection error occurred when attempting to connect to Internet"
                            " Archive to get info for search term '%s' - is internet connection"
                            " active? Waiting %s minutes before retrying (will retry %s more times)"
                        ),
                        search,
                        int(connection_wait_timer / 60),
                        MAX_RETRIES - connection_retry_counter,
                    )

                    time.sleep(connection_wait_timer)
                    connection_retry_counter += 1
                    connection_wait_timer *= (
                        2  # Add some delay for each retry in case connection issue is ongoing
                    )
                else:
                    log.warning(
                        (
                            "Connection error persisted when attempting to connect to Internet"
                            " Archive - is internet connection active? Download of search term '%s'"
                            " items have failed"
                        ),
                        search,
                    )
                    return []
            # If no further errors, break from the True loop
            else:
                break
    return identifiers


def main() -> None:
    """Captures args via argparse and sets up either downloading threads or verification check"""
    run_time = datetime.datetime.now()
    datetime_string = run_time.strftime("%Y%m%d_%H%M%S")

    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "-l",
        "--logfolder",
        type=str,
        default="ia_downloader_logs",
        help=(
            "Folder to write logs to (if not specified, folder 'ia_downloader_logs' will be used in"
            " same directory as this script)"
        ),
    )

    subparsers = parser.add_subparsers(
        help=(
            "Either 'download' files associated with an Internet Archive identifier, or 'verify' a"
            " previously-completed download was successful and files match expected MD5 hash values"
        ),
        dest="command",
        required=True,
    )

    download_parser = subparsers.add_parser("download")
    download_parser.add_argument(
        "-i",
        "--identifiers",
        type=str,
        nargs="*",
        help=(
            "One or more (space separated) Archive.org identifiers (e.g."
            " 'gov.archives.arc.1155023')"
        ),
    )
    download_parser.add_argument(
        "-s",
        "--search",
        type=str,
        nargs="*",
        help=(
            "One or more (space separated) Archive.org search terms to run - all items"
            " returned by the search will be downloaded. Search term can be built at"
            " https://archive.org/advancedsearch.php then copied across"
        ),
    )
    download_parser.add_argument(
        "-o",
        "--output",
        type=str,
        default="internet_archive_downloads",
        help="Folder to download files to",
    )
    download_parser.add_argument(
        "-t",
        "--threads",
        type=check_argument_int_greater_than_one,
        default=5,
        help=(
            "Number of download threads (i.e. how many downloads to perform simultaneously)"
            " (default is 5)"
        ),
    )
    download_parser.add_argument(
        "-v",
        "--verify",
        default=False,
        action="store_true",
        help="Perform an MD5 hash check on each file as downloads complete",
    )
    download_parser.add_argument(
        "-r",
        "--resume",
        default=False,
        action="store_true",
        help=(
            "Attempt to resume downloads using already-downloaded data if a connection error occurs"
        ),
    )
    download_parser.add_argument(
        "--split",
        type=check_argument_int_greater_than_one,
        default=1,
        help=(
            "To increase per-file download speeds, split files above 10MB into provided number of"
            " chunks, and reconstruct on completion"
        ),
    )
    download_parser.add_argument(
        "-f",
        "--filefilters",
        type=str,
        nargs="+",
        help=(
            "One or more (space separated) file name filters; only files that contain any of the"
            " provided filter strings (case insensitive) will be downloaded. If multiple filters"
            " are provided, the search will be an 'OR' (i.e. only one of the provided strings needs"
            " to hit)"
        ),
    )
    download_parser.add_argument(
        "--invertfilefiltering",
        default=False,
        action="store_true",
        help=(
            "Invert file filtering logic so that only files NOT matching filefilters will be"
            " downloaded"
        ),
    )
    download_parser.add_argument(
        "-c",
        "--credentials",
        type=str,
        nargs=2,
        help=(
            "Email address and password (as separate strings) for Internet Archive account"
            " (required for download of some Internet Archive items)"
        ),
    )
    download_parser.add_argument(
        "--hashfile",
        type=str,
        help=(
            "Output path to write file containing hash metadata to (if not specified, file will"
            " be created in the output folder)"
        ),
    )
    download_parser.add_argument(
        "--cacherefresh",
        default=False,
        action="store_true",
        help="Flag to update any cached Internet Archive metadata from previous script executions",
    )

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument(
        "data_folders",
        type=str,
        nargs="+",
        help="Path to folder containing previously downloaded data",
    )
    verify_parser.add_argument(
        "-i",
        "--identifiers",
        type=str,
        nargs="+",
        help=(
            "One or more (space separated) Archive.org identifiers (e.g."
            " 'gov.archives.arc.1155023') - to be used if only certain item(s) in the target"
            " folder(s) are to be verified"
        ),
    )
    verify_parser.add_argument(
        "--hashfile",
        type=str,
        help=(
            "Path to file containing hash metadata from previous download using this script (if not"
            " specified, cached data from previous script execution will be used)"
        ),
    )
    verify_parser.add_argument(
        "-f",
        "--filefilters",
        type=str,
        nargs="+",
        help=(
            "One or more (space separated) file name filters; only files that contain any of the"
            " provided filter strings (case insensitive) will be verified. If multiple filters"
            " are provided, the search will be an 'OR' (i.e. only one of the provided strings needs"
            " to hit)"
        ),
    )
    verify_parser.add_argument(
        "--invertfilefiltering",
        default=False,
        action="store_true",
        help=(
            "Invert file filtering logic so that only files NOT matching filefilters will be"
            " verified"
        ),
    )
    verify_parser.add_argument(
        "--nopaths",
        default=False,
        action="store_true",
        help=(
            "If files are no longer in the same relative paths, perform lookup based only on"
            " whether MD5 hashes are present in the data set (rather than also checking where those"
            " files are stored)"
        ),
    )

    args = parser.parse_args()

    # Set up logging
    log_subfolders = ["logs", "cache"]
    for log_subfolder in log_subfolders:
        pathlib.Path(os.path.join(args.logfolder, log_subfolder)).mkdir(parents=True, exist_ok=True)
    log, counter_handler = prepare_logging(
        datetime_string,
        os.path.join(args.logfolder, log_subfolders[0]),
        "ia_downloader",
        dict(vars(args)),
    )
    if args.filefilters is None and args.invertfilefiltering:
        log.warning("--invertfilefiltering flag will be ignored as no file filters were provided")
    log.info(
        "Internet Archive is a non-profit organisation that is experiencing unprecedented service"
        " demand. Please consider making a donation: https://archive.org/donate"
    )
    log.info("Logs will be stored in folder '%s'", args.logfolder)

    try:
        if args.command == "download":
            if args.identifiers is None and args.search is None:
                log.error("No identifiers (-i) or searches (-s) have been provided for download")
                return
            if args.credentials is not None:
                try:
                    internetarchive.configure(args.credentials[0], args.credentials[1])
                except internetarchive.exceptions.AuthenticationError:
                    log.error(
                        "Authentication error raised for supplied email address and password -"
                        " check these were entered correctly (if the password has spaces, it must"
                        " be wrapped in quotation marks)"
                    )
                    return
            if args.hashfile is not None:
                log.info(
                    "Internet Archive metadata will be written to hash file at '%s'", args.hashfile
                )
            if args.threads > 5 or args.split > 5:
                log.info(
                    "Reducing download threads to 5, to optimise script performance and reduce"
                    " Internet Archive server load"
                )
                args.threads = min(args.threads, 5)
                args.split = min(args.split, 5)
            if args.split > 1:
                if args.threads > 1:
                    log.info(
                        "While using file splitting, only one file will be downloaded at a time so"
                        " as to not overwhelm Internet Archive servers"
                    )
                    args.threads = 1
            hashfile_file_handler = None
            if args.hashfile:
                hashfile_file_handler = open(args.hashfile, "w", encoding="utf-8")
            identifiers = args.identifiers if args.identifiers is not None else []
            if args.search:
                for search in args.search:
                    identifiers.extend(
                        get_identifiers_from_search_term(
                            search=search,
                            cache_parent_folder=os.path.join(args.logfolder, log_subfolders[1]),
                            cache_refresh=args.cacherefresh,
                        )
                    )
            for identifier in identifiers:
                download(
                    identifier=identifier,
                    output_folder=args.output,
                    hash_file=hashfile_file_handler,
                    thread_count=args.threads,
                    resume_flag=args.resume,
                    verify_flag=args.verify,
                    split_count=args.split,
                    file_filters=args.filefilters,
                    invert_file_filtering=args.invertfilefiltering,
                    cache_parent_folder=os.path.join(args.logfolder, log_subfolders[1]),
                    cache_refresh=args.cacherefresh,
                )

            if hashfile_file_handler is not None:
                hashfile_file_handler.close()

        elif args.command == "verify":
            verify(
                hash_file=args.hashfile,
                data_folders=args.data_folders,
                no_paths_flag=args.nopaths,
                hash_flag=True,
                cache_parent_folder=os.path.join(args.logfolder, log_subfolders[1]),
                identifiers=args.identifiers,
                file_filters=args.filefilters,
                invert_file_filtering=args.invertfilefiltering,
            )

        if counter_handler.count["WARNING"] > 0 or counter_handler.count["ERROR"] > 0:
            log.warning(
                (
                    "Script complete; %s warnings/errors occurred requiring review (see log entries"
                    " above, replicated in folder '%s')"
                ),
                counter_handler.count["WARNING"] + counter_handler.count["ERROR"],
                args.logfolder,
            )
        else:
            log.info("Script complete; no errors reported")

    except KeyboardInterrupt:
        log.warning(
            "KeyboardInterrupt received, quitting immediately (any in-progress downloads or"
            " verifications have been terminated)"
        )
    except Exception:  # pylint: disable=broad-exception-caught
        log.exception("Exception occurred:")


if __name__ == "__main__":
    # Entry point when running script directly
    main()
