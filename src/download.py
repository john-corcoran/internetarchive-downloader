import io
import logging
import multiprocessing
import multiprocessing.pool
import os
import pathlib
from typing import Optional, List
from src.ia_downloader import hash_pool_initializer
from src.download_queue import DownloadQueue
from src.item_metadata import MetadataItem


def check_file_filters(file_filters, file_name, invert_file_filtering):
    if file_filters is not None:
        if not invert_file_filtering:
            return any(substring.lower() in file_name.lower() for substring in file_filters)
        return not any(substring.lower() in file_name.lower() for substring in file_filters)
    return True


def write_file_info(identifier, file, cache_file_handler, item, log):
    if "size" not in file:
        file["size"] = -1
        log.debug("'%s' has no size metadata", file["name"])
    if "mtime" not in file:
        file["mtime"] = -1
        log.debug("'%s' has no mtime metadata", file["name"])
    log_write_str = f"{identifier}|{file['name']}|{file['size']}|{file['md5']}|{file['mtime']}\n"
    if item.is_empty:
        cache_file_handler.write(log_write_str)
    return log_write_str


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
    cache_refresh: bool,
    logfolder
) -> None:
    """Download files associated with an Internet Archive identifier"""
    log = logging.getLogger(__name__)

    pathlib.Path(output_folder).mkdir(parents=True, exist_ok=True)

    log.info("'%s' contents will be downloaded to '%s'",
             identifier, output_folder)

    hash_pool = None
    if verify_flag:
        hash_pool = multiprocessing.Pool(
            processes=multiprocessing.cpu_count() - 1,
            initializer=hash_pool_initializer)

    cache_folder = os.path.join(cache_parent_folder, identifier)
    item = MetadataItem.from_cache(
        identifier=identifier,
        cache_parent_folder=cache_parent_folder,
        cache_refresh=cache_refresh,
        log=log
    )

    if item.is_empty:
        item = MetadataItem.from_internet_archive(
            identifier=identifier,
            max_retries=5,
            log=log)
        if item.is_empty:
            log.warning("Metadata item could not be fetched.")

    cache_folder = os.path.join(cache_parent_folder, identifier)
    pathlib.Path(cache_folder).mkdir(parents=True, exist_ok=True)

    download_queue = DownloadQueue(
        item=item,
        cache_folder=cache_folder,
        identifier=identifier,
        log=log,
        file_filters=file_filters,
        invert_file_filtering=invert_file_filtering,
        hash_file=hash_file,
        output_folder=output_folder,
        hash_pool=hash_pool,
        resume_flag=resume_flag,
        split_count=split_count,
        logfolder=logfolder
    )

    download_queue.process(thread_count=thread_count)

    if hash_pool is not None:
        log.debug("Waiting for hash tasks to complete")
        hash_pool.close()
        hash_pool.join()
