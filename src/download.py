import datetime
import io
import logging
import multiprocessing
import multiprocessing.pool
import os
import pathlib
import time
from typing import Tuple, Optional, List
import internetarchive
import requests
from ia_downloader import file_paths_in_folder, hash_pool_initializer, verify, bytes_filesize_to_readable_str, file_download


class CacheDict:
    """Using this simply to allow for a custom attribute (item_metadata) if we use cache"""

def get_item_from_cache(
    identifier: str,
    cache_parent_folder: str,
    cache_refresh: bool,
    log: logging.Logger
) -> Optional[CacheDict]:
    """Get item data from cache if available and fresh"""
    cache_folder = os.path.join(cache_parent_folder, identifier)

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
                    "Cached data from {} will be used for item '{}'".format(
                        datetime_str, identifier
                    )
                )
                item = CacheDict()
                item.item_metadata = {}
                item.item_metadata["files"] = []
                with open(cache_file, "r", encoding="UTF-8") as file_handler:
                    try:
                        for line in file_handler:
                            _, file_path, size, md5, mtime = line.strip().split("|")
                            item_dict = {}
                            item_dict["name"] = file_path
                            item_dict["size"] = size
                            item_dict["md5"] = md5
                            item_dict["mtime"] = mtime
                            item.item_metadata["files"].append(item_dict)
                    except ValueError:
                        log.info(
                            "Cache file '{}' does not match expected format - cache data will"
                            " be redownloaded".format(cache_file)
                        )
                        return None
                return item
    return None

def get_item_metadata(
    identifier: str,
    max_retries: int,
    log: logging.Logger
) -> Optional[dict]:
    connection_retry_counter = 0
    connection_wait_timer = 600
    item = None
    while True:
        try:
            item = internetarchive.get_item(identifier)
            if "item_last_updated" in item.item_metadata:
                item_updated_time = datetime.datetime.fromtimestamp(
                    int(item.item_metadata["item_last_updated"])
                )
                if item_updated_time > (datetime.datetime.now() - datetime.timedelta(weeks=1)):
                    log.warning(
                        "Internet Archive item '{}' was updated within the last week (last"
                        " updated on {}) - verification/corruption issues may occur if"
                        " files are being updated by the uploader. If such errors occur"
                        " when resuming a download, recommend using the '--cacherefresh'"
                        " flag".format(
                            identifier, item_updated_time.strftime("%Y-%m-%d %H:%M:%S")
                        )
                    )
        except requests.exceptions.ConnectionError:
            if connection_retry_counter < max_retries:
                log.info(
                    "ConnectionError occurred when attempting to connect to Internet"
                    " Archive to get info for item '{}' - is internet connection active?"
                    " Waiting {} minutes before retrying (will retry {} more times)".format(
                        identifier,
                        int(connection_wait_timer / 60),
                        max_retries - connection_retry_counter,
                    )
                )
                time.sleep(connection_wait_timer)
                connection_retry_counter += 1
                connection_wait_timer *= (
                    2  # Add some delay for each retry in case connection issue is ongoing
                )
            else:
                log.warning(
                    "ConnectionError persisted when attempting to connect to Internet"
                    " Archive - is internet connection active? Download of item '{}' has"
                    " failed".format(identifier)
                )
                return None
        else:
            break
    return item

def generate_download_queue(
    item,
    cache_folder,
    identifier,
    log,
    file_filters=None,
    invert_file_filtering=False,
    hash_file=None,
    output_folder=None,
    hash_pool=None,
    resume_flag=None,
    split_count=None
):
    """
    This function generates a download queue for files, based on given conditions and filters.
    
    Args:
        item: The item metadata to generate download queue from.
        cache_folder: The folder to cache downloaded items.
        identifier: The identifier of the item.
        log: The logger for debug and info messages.
        file_filters (optional): The substrings to filter files by.
        invert_file_filtering (optional): A flag to invert file filtering.
        hash_file (optional): The file to write the hash log.
        output_folder (optional): The folder to output the downloaded items.
        hash_pool (optional): The pool of hashes.
        resume_flag (optional): The flag to resume or not.
        split_count (optional): The count to split files.
    
    Returns:
        A tuple (item_file_count, item_total_size, item_filtered_files_size, download_queue)
    """

    item_file_count = 0
    item_total_size = 0
    item_filtered_files_size = 0
    download_queue = []

    # If the 'item' is our custom CacheDict, then we built it from cache - so don't need to
    # write another metadata file
    metadata_folder = os.path.join(
        cache_folder,
        f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{identifier}_metadata.txt"
    )

    for file in item.item_metadata["files"]:
        item_file_count += 1
        if "size" in file:
            item_total_size += int(file["size"])
        # In testing it seems that the '[identifier]_files.xml' file will not have size
        # or mtime data; the below will set a default size/mtime of '-1' where needed
        if "size" not in file:
            file["size"] = -1
            log.debug("'{}' has no size metadata".format(file["name"]))
        if "mtime" not in file:
            file["mtime"] = -1
            log.debug("'{}' has no mtime metadata".format(file["name"]))
        log_write_str = "{}|{}|{}|{}|{}\n".format(
            identifier, file["name"], file["size"], file["md5"], file["mtime"]
        )
        if not isinstance(item, CacheDict):
            with open(metadata_folder, "w", encoding="UTF-8") as cache_file_handler:
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
            )
        )

    return (item_file_count, item_total_size, item_filtered_files_size, download_queue)

def check_file_filters(file_filters, file_name, invert_file_filtering):
    if file_filters is not None:
        if not invert_file_filtering:
            return any(substring.lower() in file_name.lower() for substring in file_filters)
        else:
            return not any(substring.lower() in file_name.lower() for substring in file_filters)
    return True


def write_file_info(identifier, file, cache_file_handler, item, log):
    if "size" not in file:
        file["size"] = -1
        log.debug("'{}' has no size metadata".format(file["name"]))
    if "mtime" not in file:
        file["mtime"] = -1
        log.debug("'{}' has no mtime metadata".format(file["name"]))
    log_write_str = "{}|{}|{}|{}|{}\n".format(
        identifier, file["name"], file["size"], file["md5"], file["mtime"]
    )
    if not isinstance(item, CacheDict):
        cache_file_handler.write(log_write_str)
    return log_write_str


def add_to_download_queue(
        identifier,
        file,
        output_folder,
        hash_pool,
        resume_flag,
        split_count,
        download_queue
    ):
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


def download_files(
        identifier,
        item,
        output_folder,
        hash_file,
        file_filters,
        invert_file_filtering,
        hash_pool,
        resume_flag,
        split_count,
        thread_count,
        cache_parent_folder,
        log
    ):
    item_file_count = 0
    item_total_size = 0
    item_filtered_files_size = 0
    download_queue = []

    cache_folder = os.path.join(cache_parent_folder, identifier)
    pathlib.Path(cache_folder).mkdir(parents=True, exist_ok=True)

    cache_file_handler = None
    if not isinstance(item, CacheDict):
        cache_file_handler = open(
            os.path.join(
                cache_folder,
                f"{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}_{identifier}_metadata.txt"
            ), "w", encoding="UTF-8"
        )

    for file in item.item_metadata["files"]:
        item_file_count += 1
        if "size" in file:
            item_total_size += int(file["size"])
        log_write_str = write_file_info(identifier, file, cache_file_handler, item, log)
        if check_file_filters(file_filters, file["name"], invert_file_filtering):
            if file["size"] != -1:
                item_filtered_files_size += int(file["size"])
            if hash_file is not None:
                hash_file.write(log_write_str)
            add_to_download_queue(identifier, file, output_folder, hash_pool, resume_flag, split_count, download_queue)

    if cache_file_handler is not None:
        cache_file_handler.close()

    return download_queue, item_file_count, item_total_size, item_filtered_files_size


def process_download_queue(identifier,
                           output_folder,
                           file_filters,
                           invert_file_filtering,
                           download_queue,
                           item_file_count,
                           item_total_size,
                           item_filtered_files_size,
                           hash_file,
                           thread_count,
                           cache_parent_folder,
                           log):
    identifier_output_folder = os.path.join(output_folder, identifier)
    if os.path.isdir(identifier_output_folder) and len(file_paths_in_folder(identifier_output_folder)) > 0:
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
                "'{}' appears to have been fully downloaded in folder '{}' - skipping".format(
                    identifier, output_folder
                )
            )
            return

    if file_filters is not None:
        if not invert_file_filtering:
            if len(download_queue) > 0:
                log.info(
                    "{} files ({}) match file filter(s) '{}' (case insensitive) and will be"
                    " downloaded (out of a total of {} files ({}) available)".format(
                        len(download_queue),
                        bytes_filesize_to_readable_str(item_filtered_files_size),
                        " ".join(file_filters),
                        item_file_count,
                        bytes_filesize_to_readable_str(item_total_size),
                    )
                )
            else:
                log.info(
                    "No files match the filter(s) '{}' in item '{}' - no downloads will be"
                    " performed".format(" ".join(file_filters), identifier)
                )
                return
        else:
            if len(download_queue) > 0:
                log.info(
                    "{} files ({}) NOT matching file filter(s) '{}' (case insensitive) will"
                    " be downloaded (out of a total of {} files ({}) available)".format(
                        len(download_queue),
                        bytes_filesize_to_readable_str(item_filtered_files_size),
                        " ".join(file_filters),
                        item_file_count,
                        bytes_filesize_to_readable_str(item_total_size),
                    )
                )
            else:
                log.info(
                    "All files are excluded by filter(s) '{}' in item '{}' - no downloads"
                    " will be performed".format(" ".join(file_filters), identifier)
                )
                return
    else:
        log.info(
            "'{}' contains {} files ({})".format(
                identifier,
                len(download_queue),
                bytes_filesize_to_readable_str(item_total_size),
            )
        )

    with multiprocessing.pool.ThreadPool(thread_count) as download_pool:
        download_pool.map(file_download, download_queue, chunksize=1)
        log.debug("Waiting for download pool to complete")
        download_pool.close()
        download_pool.join()

    log.info("Download phase complete for item '{}'".format(identifier))
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

def download(
    identifier: str,
    output_folder: str,
    hash_file: Optional[io.TextIOWrapper],
    thread_count: int,
    resume_flag: bool,
    verify_flag: bool,
    split_count: int,
    file_filters: Optional[List[str]],
    invert_file_filtering: bool,
    cache_parent_folder: str,
    cache_refresh: bool
) -> None:
    """Download files associated with an Internet Archive identifier"""
    log = logging.getLogger(__name__)
    PROCESSES = multiprocessing.cpu_count() - 1
    MAX_RETRIES = 5

    pathlib.Path(output_folder).mkdir(parents=True, exist_ok=True)

    log.info("'%s' contents will be downloaded to '%s'",
             identifier, output_folder)

    hash_pool = None
    if verify_flag:
        hash_pool = multiprocessing.Pool(PROCESSES, initializer=hash_pool_initializer)

    cache_folder = os.path.join(cache_parent_folder, identifier)
    item = get_item_from_cache(identifier, cache_parent_folder, cache_refresh, log)

    if item is None:
        item = get_item_metadata(identifier, MAX_RETRIES, log)
        if item is None:
            return

    download_queue, item_file_count, item_total_size, item_filtered_files_size = download_files(
        identifier,
        item,
        output_folder,
        hash_file,
        file_filters,
        invert_file_filtering,
        hash_pool,
        resume_flag,
        split_count,
        thread_count,
        cache_parent_folder=cache_folder,
        log=log
    )

    process_download_queue(
        identifier,
        output_folder,
        file_filters,
        invert_file_filtering,
        download_queue,
        item_file_count,
        item_total_size,
        item_filtered_files_size,
        hash_file,
        thread_count,
        cache_parent_folder=cache_folder,
        log=log
    )

    if hash_pool is not None:
        log.debug("Waiting for hash tasks to complete")
        hash_pool.close()
        hash_pool.join()
