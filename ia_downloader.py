#!/usr/bin/env python3

"""Script to perform simultaneous, resumable and hash-verified downloads from Internet Archive"""

import argparse
import datetime
import hashlib
import logging
import multiprocessing
import multiprocessing.pool
import os
import pathlib
import signal
import sys
import time
import typing

import internetarchive
import requests
import tqdm


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


def prepare_logging(
    datetime_string: str, folder_path: str, identifier: str
) -> typing.Tuple[logging.Logger, MsgCounterHandler]:
    """Prepare and return logging object to be used throughout script"""
    # INFO events and above will be written to both the console and a log file
    # DEBUG events and above will be written only to a (separate) log file
    log = logging.getLogger(__name__)
    log.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    debug_log = logging.FileHandler(
        os.path.join(folder_path, "{}_{}_debug.log".format(datetime_string, identifier))
    )
    debug_log.setLevel(logging.DEBUG)
    debug_log.setFormatter(formatter)
    info_log = logging.FileHandler(
        os.path.join(folder_path, "{}_{}_info.log".format(datetime_string, identifier))
    )
    info_log.setLevel(logging.INFO)
    info_log.setFormatter(formatter)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    counter_handler = MsgCounterHandler()
    log.addHandler(debug_log)
    log.addHandler(info_log)
    log.addHandler(console_handler)
    log.addHandler(counter_handler)
    return log, counter_handler


def check_argument_int_greater_than_one(value: str) -> int:
    """Confirm numeric values provided as command line arguments are >= 1"""
    ivalue = int(value)
    if ivalue <= 0:
        raise argparse.ArgumentTypeError("{} is an invalid positive int value".format(value))
    return ivalue


def file_paths_in_folder(folder_path: str) -> typing.List[str]:
    """Return sorted list of paths of files at a directory (and its subdirectories)"""
    file_paths = []
    for root, dirs, file_names in os.walk(folder_path):
        for name in file_names:
            file_paths.append(os.path.join(root, name))
    return sorted(file_paths)


def get_metadata_from_hashfile(hash_file_path: str, hash_flag: bool) -> typing.Dict[str, str]:
    """Return dict of file paths and associated metadata parsed from IA hash metadata CSV"""
    results = {}  # type: typing.Dict[str, str]
    with open(hash_file_path, "r", encoding="utf-8") as file_handler:
        for line in file_handler:
            file_path, size, md5 = line.strip().split("|")
            if hash_flag:
                results[os.path.normpath(file_path)] = md5.lower().strip()
            else:
                results[os.path.normpath(file_path)] = size.lower().strip()
    return results


def get_metadata_from_files_in_folder(folder_path: str, hash_flag: bool) -> typing.Dict[str, str]:
    """Return dict of file paths and metadata of files at a directory (and its subdirectories)"""
    results = {}  # type: typing.Dict[str, str]
    file_paths = file_paths_in_folder(folder_path)
    if hash_flag:
        for file_path in tqdm.tqdm(file_paths):
            md5 = md5_hash_file(file_path)
            results[os.path.normpath(os.path.relpath(file_path, folder_path))] = md5.lower().strip()
    else:
        # Return file sizes if we're not checking hash values
        for file_path in file_paths:
            file_size = os.path.getsize(file_path)
            results[os.path.normpath(os.path.relpath(file_path, folder_path))] = str(file_size)
    return results


def md5_hash_file(filepath: str) -> str:
    """Return str containing lowercase MD5 hash value of a file"""
    block_size = 64 * 1024
    md5 = hashlib.md5()
    with open(filepath, "rb") as file_handler:
        while True:
            data = file_handler.read(block_size)
            if not data:
                break
            md5.update(data)
    return md5.hexdigest()


def hash_pool_initializer():
    """Ignore CTRL+C in the hash worker processes (workers are daemonic so will close when the
    main process terminates)

    """
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def check_hash(file_path: str, md5_value_from_ia: str) -> typing.Tuple[str, str]:
    """Called as a separate process from the file_download function; returns results from an MD5
    hash check of a file

    """
    md5_value_local = md5_hash_file(file_path)
    if md5_value_local.lower().strip() == md5_value_from_ia.lower().strip():
        return (
            "debug",
            "'{}' file hash ('{}') matches between local file and IA metadata".format(
                os.path.basename(file_path), md5_value_local
            ),
        )
    return (
        "warning",
        "'{}' file hash does not match between local file ('{}') and IA metadata ('{}')".format(
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
    if chunk_number is not None:
        dest_file_path += ".{}".format(chunk_number)
        dest_file_name = os.path.basename(dest_file_path)
        expected_file_size = bytes_range[1] - bytes_range[0] + 1

    # If the destination file path exists already (i.e. file has already been (at least partially)
    # downloaded), but the file size doesn't match expectations (i.e. download was incomplete),
    # either re-download from scratch or attempt resume, depending on resume_flag argument
    if os.path.isfile(dest_file_path):
        if ia_file_size != -1:  # -1 denotes that IA metadata does not contain size info
            downloaded_file_size = os.path.getsize(dest_file_path)
            if downloaded_file_size == expected_file_size:
                log.debug(
                    "'{}' will be skipped as file with expected file size already present at '{}'"
                    .format(dest_file_name, dest_file_path)
                )
                return
            else:
                if downloaded_file_size < expected_file_size:
                    if resume_flag:
                        log.info(
                            "'{}' exists as downloaded file '{}' but file size indicates download"
                            " was not completed; will be resumed ({:.1%} remaining)".format(
                                dest_file_name,
                                dest_file_path,
                                1 - (downloaded_file_size / expected_file_size),
                            )
                        )
                    else:
                        log.info(
                            "'{}' exists as downloaded file '{}' but file size indicates download"
                            " was not completed; will be redownloaded".format(
                                dest_file_name, dest_file_path
                            )
                        )
                else:
                    log.warning(
                        "'{}' exists as downloaded file '{}', but with a larger file size than"
                        " expected - was the file modified (either locally or on Internet Archive)"
                        " since it was downloaded?".format(dest_file_name, dest_file_path)
                    )
                    return
        else:
            log.info(
                "'{}' exists as downloaded file '{}' but file size metadata unavailable from IA to"
                " confirm whether file size is as expected; will be redownloaded".format(
                    dest_file_name, dest_file_path
                )
            )

    # If this thread is expected to create new threads for split file downloading, first need to
    # check that the web server returns a 206 status code with a 'Range' request, indicating the
    # requested can be split
    if split_count > 1 and ia_file_size > file_size_split_limit:
        response_list = internetarchive.download(
            identifier,
            files=[ia_file_name],
            destdir=output_folder,
            on_the_fly=True,
            silent=True,
            return_responses=True,
        )
        response = response_list[0]  # type: requests.Response
        request = response.request  # type: requests.PreparedRequest
        headers = request.headers
        # We're just testing this connection, so don't need the whole byte range
        headers["Range"] = "bytes={}-{}".format(0, 10)

        new_response = requests.get(request.url, headers=headers, timeout=12, stream=True)

        if new_response.status_code == 206:
            log.debug(
                "'{}' returns a 206 status when requesting a Range - can therefore split download"
                .format(ia_file_name)
            )
        elif new_response.status_code == 200:
            log.debug(
                "'{}' returns a 200 status when requesting a Range - download will not be split"
                .format(ia_file_name)
            )
            split_count = 1
        else:
            log.info(
                "Unexpected status code {} returned for file '{}' when testing file splitting -"
                " download will be attempted without splitting".format(
                    new_response.status_code, ia_file_name
                )
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
            log.info("'{}' will be downloaded in {} parts".format(ia_file_name, split_count))
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
                    "'{}' chunk {} (sub-file '{}') cannot be found".format(
                        ia_file_name, chunk_counter, chunk_file_path
                    )
                )
                failed_indicator = True
            elif os.path.getsize(chunk_file_path) != chunk_sizes[chunk_counter]:
                log.warning(
                    "'{}' chunk {} (sub-file '{}') is not the expected size (expected size {},"
                    " actual size {})".format(
                        ia_file_name,
                        chunk_counter,
                        chunk_file_path,
                        chunk_sizes[chunk_counter],
                        os.path.getsize(chunk_file_path),
                    )
                )
                failed_indicator = True

        if failed_indicator:
            log.warning(
                "Error occurred with file chunks for file {} - file could not be reconstructed"
                " and has therefore not been downloaded successfully".format(ia_file_name)
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
        connection_wait_timer = 300
        size_wait_timer = 300
        while True:
            try:
                if not resume_flag and chunk_number is None:
                    log.info("Beginning download of '{}'".format(dest_file_name))
                    internetarchive.download(
                        identifier,
                        files=[ia_file_name],
                        destdir=output_folder,
                        on_the_fly=True,
                        silent=True,
                    )
                else:
                    if os.path.isfile(dest_file_path):
                        if ia_file_size == -1 or not resume_flag:
                            # If we don't have size metadata from IA (i.e. if file_size == -1), then
                            # perform a full re-download. (Although we could run a hash check
                            # instead, in testing it seems that any IA file that lacks size metadata
                            # will also give different hash values per download - so would be
                            # wasting time to calc hash as there'll always be a mismatch requiring
                            # a full re-download)
                            log.info("Redownloading '{}'".format(dest_file_name))
                            file_write_mode = "wb"
                        elif resume_flag:
                            log.info("Resuming download of '{}'".format(dest_file_name))
                            file_write_mode = "ab"
                    else:
                        log.info("Beginning download of '{}'".format(dest_file_name))
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
                    response_list = internetarchive.download(
                        identifier,
                        files=[ia_file_name],
                        destdir=output_folder,
                        on_the_fly=True,
                        silent=True,
                        return_responses=True,
                    )
                    response = response_list[0]  # type: requests.Response
                    request = response.request  # type: requests.PreparedRequest
                    headers = request.headers

                    if os.path.isfile(dest_file_path) and ia_file_size != -1 and resume_flag:
                        downloaded_file_size = os.path.getsize(dest_file_path)
                        # If we don't have bytes_range yet, this download isn't a file chunk, so
                        # just download all the remaining file data
                        if bytes_range is None:
                            bytes_range = (downloaded_file_size, ia_file_size - 1)
                        # Otherwise, this is a file chunk, so only download up to the final amount
                        # needed for this chunk
                        else:
                            upper_bytes_range = bytes_range[0] + downloaded_file_size
                            bytes_range = (upper_bytes_range, bytes_range[1])

                    # Set the bytes range if we're either resuming a download or downloading a file
                    # chunk
                    if bytes_range is not None:
                        headers["Range"] = "bytes={}-{}".format(bytes_range[0], bytes_range[1])

                    new_response = requests.get(
                        request.url, headers=headers, timeout=12, stream=True
                    )

                    log.debug(
                        "{} status for request for file '{}'".format(
                            new_response.status_code, ia_file_name
                        )
                    )

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

            except requests.exceptions.ConnectionError:
                if connection_retry_counter < MAX_RETRIES:
                    log.info(
                        "ConnectionError occurred for '{}', waiting {} minutes before retrying"
                        " (will retry {} more times)".format(
                            dest_file_name,
                            int(connection_wait_timer / 60),
                            MAX_RETRIES - connection_retry_counter,
                        )
                    )
                    time.sleep(connection_wait_timer)
                    connection_retry_counter += 1
                    connection_wait_timer *= (
                        2  # Add some delay for each retry in case connection issue is ongoing
                    )
                else:
                    log.warning(
                        "'{}' download timed out {} times; this file has not been downloaded"
                        " successfully".format(dest_file_name, MAX_RETRIES)
                    )
                    return

            else:
                # In testing, have seen rare instances of the file not being fully downloaded
                # despite the response object not reporting any more data to write. Perhaps the
                # server sometimes terminates the connection? So let's check the file is the
                # expected size and restart/resume the download if not
                downloaded_file_size = os.path.getsize(dest_file_path)
                if ia_file_size != -1 and downloaded_file_size < expected_file_size:
                    if size_retry_counter < MAX_RETRIES:
                        log.info(
                            "File '{}' download concluded but file size is not as expected (file"
                            " size is {} bytes, expected {} bytes). The server possibly terminated"
                            " the connection - waiting {} minutes before retrying (will retry {}"
                            " more times)".format(
                                dest_file_name,
                                downloaded_file_size,
                                expected_file_size,
                                int(size_wait_timer / 60),
                                MAX_RETRIES - size_retry_counter,
                            )
                        )
                        time.sleep(size_wait_timer)
                        size_retry_counter += 1
                        size_wait_timer *= (
                            2  # Add some delay for each retry in case connection issue is ongoing
                        )
                    else:
                        log.warning(
                            "Failed to increase downloaded file '{}' to expected file size (final"
                            " file size is {}, expected {}; this file has not been downloaded"
                            " successfully".format(
                                dest_file_name, downloaded_file_size, expected_file_size
                            )
                        )
                        return

                # If no further errors, break from the True loop
                break

    complete_time = datetime.datetime.now()
    duration = complete_time - start_time
    duration_in_minutes = round(duration.total_seconds() / 60, 2)
    filesize_in_mb = (expected_file_size / 1024) / 1024
    log.info(
        "'{}' download completed in {} minutes ({}MB per minute)".format(
            dest_file_name,
            duration_in_minutes,
            round(filesize_in_mb / duration_in_minutes, 1),
        )
    )

    # If user has opted to verify downloads, add the task to the hash_pool
    if chunk_number is None:  # Only hash if we're in a thread that isn't downloading a file chunk
        if hash_pool is not None:
            hash_pool.starmap_async(
                check_hash, iterable=[(dest_file_path, ia_md5)], callback=log_update_callback
            )


def download(
    identifier: str,
    output_folder: str,
    hash_file: str,
    thread_count: int,
    resume_flag: bool,
    verify_flag: bool,
    split_count: int,
    file_filters: typing.Optional[typing.List[str]],
) -> None:
    """Download files associated with an Internet Archive identifier"""
    log = logging.getLogger(__name__)
    PROCESSES = multiprocessing.cpu_count() - 1

    pathlib.Path(output_folder).mkdir(parents=True, exist_ok=True)

    log.info(
        "'{}' contents will be downloaded to '{}'".format(
            identifier, os.path.join(output_folder, identifier)
        )
    )

    # Get Internet Archive metadata for the provided identifier
    try:
        item = internetarchive.get_item(identifier)
    except requests.exceptions.ConnectionError:
        log.error(
            "ConnectionError occurred when attempting to connect to Internet Archive - is internet"
            " connection active?"
        )
        return

    # If user has set to verify, create a new multiprocessing.Pool whose reference will be passed
    # to each download thread to allow for non-blocking hashing
    hash_pool = None
    if verify_flag:
        hash_pool = multiprocessing.Pool(PROCESSES, initializer=hash_pool_initializer)

    # Write metadata for files associated with IA identifier to a file, and populate download_queue
    # with this metadata
    total_file_count = 0
    if "files" in item.item_metadata:
        download_queue = []
        with open(hash_file, "w") as file_handler:
            for file in item.item_metadata["files"]:
                total_file_count += 1
                if file_filters is not None:
                    if not any(
                        substring.lower() in file["name"].lower() for substring in file_filters
                    ):
                        continue
                # In testing it seems that the '[identifier]_files.xml' file will not have size or
                # mtime data; the below will set a default size/mtime of '-1' where needed
                if "size" not in file:
                    file["size"] = -1
                    log.debug("'{}' has no size metadata".format(file["name"]))
                if "mtime" not in file:
                    file["mtime"] = -1
                    log.debug("'{}' has no mtime metadata".format(file["name"]))
                file_handler.write("{}|{}|{}\n".format(file["name"], file["size"], file["md5"]))
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
        if file_filters is not None:
            if len(download_queue) > 0:
                log.info(
                    "{} files match file filter(s) '{}' (case insensitive) and will be downloaded"
                    " (out of a total of {} files available); file metadata written to '{}'".format(
                        len(download_queue), " ".join(file_filters), total_file_count, hash_file
                    )
                )
            else:
                log.error(
                    "No files match the filter(s) '{}' - no downloads will be performed".format(
                        " ".join(file_filters)
                    )
                )
                os.remove(hash_file)
                return
        else:
            log.info(
                "{} files will be downloaded; file metadata written to '{}'".format(
                    len(download_queue), hash_file
                )
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

        if hash_pool is not None:
            log.debug("Waiting for hash tasks to complete")
            hash_pool.close()
            hash_pool.join()  # Blocks until hashing processes are complete

        log.info("Downloading for '{}' complete".format(identifier))

    else:
        log.error(
            "No files found associated with Internet Archive identifier '{}' (check that the"
            " correct identifier has been entered)".format(identifier)
        )


def verify(hash_file: str, data_folder: str, no_paths_flag: bool, hash_flag: bool):
    """Verify that previously-downloaded files are complete"""
    log = logging.getLogger(__name__)
    if os.path.isfile(hash_file):
        if os.path.isdir(data_folder):
            # Get comparable dictionaries from both the hash metadata file (i.e. IA-side metadata)
            # and local folder of files (i.e. local-side metadata of previously-downloaded files)
            hashfile_metadata = get_metadata_from_hashfile(hash_file, hash_flag)
            folder_metadata = get_metadata_from_files_in_folder(data_folder, hash_flag)

            if hash_flag:
                md5_or_size_str = "MD5"
            else:
                md5_or_size_str = "Size"

            # If user has moved files, so they're no longer in the same relative file paths, they
            # will need to set the 'nopaths' flag so that only hash/size metadata is checked rather
            # than path data as well
            # Disadvantage of this approach is that, if a file is stored in multiple locations, the
            # unique hash/size will only be checked for once - so any deletions of multiple copies
            # of the file will not be flagged
            if no_paths_flag:
                # Get sets of just the hash/size data from each metadata source
                hashfile_value_set = set(hashfile_metadata.values())
                folder_value_set = set(folder_metadata.values())

                # Iterate only for hashes/sizes in the IA metadata that are not present in the local
                # folder of downloaded files
                for value in [x for x in hashfile_value_set if x not in folder_value_set]:
                    log.warning(
                        "{} '{}' (original filename(s) '{}') not found in data folder".format(
                            md5_or_size_str,
                            value,
                            [k for k, v in hashfile_metadata.items() if v == value],
                        )
                    )

            else:
                for file_path, value in hashfile_metadata.items():
                    if file_path not in folder_metadata:
                        log.warning("File '{}' not found in data folder".format(file_path))
                    else:
                        if value != folder_metadata[file_path]:
                            if value != "-1":
                                log.warning(
                                    "File '{}' {} does not match ('{}' in IA metadata, '{}' in data"
                                    " folder)".format(
                                        file_path,
                                        md5_or_size_str,
                                        value,
                                        folder_metadata[file_path],
                                    )
                                )
                            else:
                                log.debug(
                                    "File '{}' {} is not available in IA metadata, so verification"
                                    " not performed on this file".format(file_path, md5_or_size_str)
                                )

        else:
            log.error("Folder '{}' does not exist".format(data_folder))
    else:
        log.error("File '{}' does not exist".format(hash_file))


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
        "identifiers",
        type=str,
        nargs="+",
        help=(
            "One or more (space separated) Archive.org identifiers (e.g."
            " 'gov.archives.arc.1155023')"
        ),
    )
    download_parser.add_argument("output_folder", type=str, help="Folder to output to")
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
            " (experimental)"
        ),
    )
    download_parser.add_argument(
        "-s",
        "--split",
        type=check_argument_int_greater_than_one,
        default=1,
        help=(
            "To increase per-file download speeds, split files above 10MB into provided number of"
            " chunks, and reconstruct on completion (experimental)"
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
        "--hashfile",
        type=str,
        help=(
            "Output path to write file containing hash metadata to (if not specified, file will"
            " be created in the output folder)"
        ),
    )

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument(
        "hashfile",
        type=str,
        help="Path to file containing hash metadata from previous download using this script",
    )
    verify_parser.add_argument(
        "data_folder",
        type=str,
        help="Path to folder containing previously downloaded data",
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
    pathlib.Path(args.logfolder).mkdir(parents=True, exist_ok=True)
    log, counter_handler = prepare_logging(datetime_string, args.logfolder, "ia_downloader")
    log.debug(sys.argv)
    log.info(
        "Internet Archive is a non-profit organisation that is experiencing unprecedented service"
        " demand. Please consider making a donation: https://archive.org/donate"
    )
    log.info("Logs will be stored in folder '{}'".format(args.logfolder))

    try:
        if args.command == "download":
            if args.threads > 5 or args.split > 5:
                log.info(
                    "Reducing download threads to 5, to optimise script performance and reduce"
                    " Internet Archive server load"
                )
                if args.threads > 5:
                    args.threads = 5
                if args.split > 5:
                    args.split = 5

            if len(args.identifiers) > 1 and args.hashfile is not None:
                log.warning(
                    "Custom hashfile path can only be used when one identifier is specified -"
                    " provided value of '{}' will therefore be ignored".format(args.hashfile)
                )
                args.hashfile = None

            if args.split > 1:
                if args.threads > 1:
                    log.info(
                        "While using file splitting, only one file will be downloaded at a time so"
                        " as to not overwhelm Internet Archive servers"
                    )
                    args.threads = 1

            for identifier in args.identifiers:
                if args.hashfile is None:
                    hash_file = os.path.join(
                        args.output_folder,
                        "{}_{}_hashes.txt".format(identifier, datetime_string),
                    )
                else:
                    hash_file = args.hashfile

                download(
                    identifier=identifier,
                    output_folder=args.output_folder,
                    hash_file=hash_file,
                    thread_count=args.threads,
                    resume_flag=args.resume,
                    verify_flag=args.verify,
                    split_count=args.split,
                    file_filters=args.filefilters,
                )

                # If no errors occurred, do a 'basic' verification of data (just checking file sizes
                # and paths, not hash values) - this is separate to hash checks that will be
                # performed as downloads complete if the user has opted to '--verify'
                if counter_handler.count["ERROR"] == 0:
                    verify(
                        hash_file=hash_file,
                        data_folder=os.path.join(args.output_folder, identifier),
                        no_paths_flag=False,
                        hash_flag=False,
                    )

        elif args.command == "verify":
            verify(
                hash_file=args.hashfile,
                data_folder=args.data_folder,
                no_paths_flag=args.nopaths,
                hash_flag=True,
            )

        if counter_handler.count["WARNING"] > 0:
            log.warning(
                "{} warnings occurred requiring review (see log entries above, replicated in folder"
                " '{}')".format(counter_handler.count["WARNING"], args.logfolder)
            )

    except KeyboardInterrupt:
        log.warning(
            "KeyboardInterrupt received, quitting immediately (any in-progress downloads or"
            " verifications have been terminated)"
        )
    except Exception:
        log.exception("Exception occurred:")


if __name__ == "__main__":
    # Entry point when running script directly
    main()
