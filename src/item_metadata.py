import datetime
import logging
import os
import time
from typing import Optional, Type
import internetarchive
import requests
from src.log import debug_decorator


class MetadataItem:
    """Using this simply to allow for a custom attribute (item_metadata) if we use cache"""

    @debug_decorator
    def __init__(
            self,
            item_metadata: Optional[dict] = None,
            is_empty: bool = False,
            internetarchive_item: Optional[any] = None
        ):
        if internetarchive_item is not None:
            self.item_metadata = internetarchive_item.item_metadata
            self.is_empty = False
        else:
            self.item_metadata = (item_metadata or {"files": []})
            self.is_empty = is_empty

    @classmethod
    @debug_decorator
    def from_cache(
        cls: Type['MetadataItem'],
        identifier: str,
        cache_parent_folder: str,
        cache_refresh: bool,
        log: logging.Logger
    ) -> 'MetadataItem':
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
                        "Cached data from %s will be used for item '%s'",
                        datetime_str, identifier
                    )
                    item = MetadataItem()
                    item.item_metadata["files"] = []
                    with open(cache_file, "r", encoding="UTF-8") as file_handler:
                        try:
                            for line in file_handler:
                                _, file_path, size, md5, mtime = line.strip().split("|")
                                item_dict = {
                                    "name": file_path,
                                    "size": size,
                                    "md5": md5,
                                    "mtime": mtime
                                }
                                item.item_metadata["files"].append(item_dict)
                        except ValueError:
                            log.info(
                                "Cache file '%s' does not match expected format - cache data will"
                                " be redownloaded",
                                cache_file
                            )
                            return MetadataItem(is_empty=True)
                    return item
        return MetadataItem(is_empty=True)

    @classmethod
    @debug_decorator
    def from_internet_archive(
        cls: Type['MetadataItem'],
        identifier: str,
        max_retries: int,
        log: logging.Logger
    ) -> 'MetadataItem':
        '''
        TODO
        '''
        connection_retry_counter = 0
        connection_wait_timer = 600
        while True:
            try:
                item = MetadataItem(
                    internetarchive_item=internetarchive.get_item(identifier))
                if "item_last_updated" in item.item_metadata:
                    item_updated_time = datetime.datetime.fromtimestamp(
                        int(item.item_metadata["item_last_updated"])
                    )
                    if item_updated_time > (datetime.datetime.now() - datetime.timedelta(weeks=1)):
                        log.warning(
                            "Internet Archive item '%s' was updated within the last week (last"
                            " updated on %s) - verification/corruption issues may occur if"
                            " files are being updated by the uploader. If such errors occur"
                            " when resuming a download, recommend using the '--cacherefresh'"
                            " flag",
                            identifier, item_updated_time.strftime("%Y-%m-%d %H:%M:%S")
                        )
            except requests.exceptions.ConnectionError:
                if connection_retry_counter < max_retries:
                    log.info(
                        "ConnectionError occurred when attempting to connect to Internet"
                        " Archive to get info for item '%s' - is internet connection active?"
                        " Waiting %d minutes before retrying (will retry %d more times)",
                        identifier,
                        int(connection_wait_timer / 60),
                        max_retries - connection_retry_counter
                    )
                    time.sleep(connection_wait_timer)
                    connection_retry_counter += 1
                    connection_wait_timer *= (
                        2  # Add some delay for each retry in case connection issue is ongoing
                    )
                else:
                    log.warning(
                        "ConnectionError persisted when attempting to connect to Internet"
                        " Archive - is internet connection active? Download of item '%s' has"
                        " failed",
                        identifier
                    )
                    return MetadataItem(is_empty=True)
            else:
                break
        return MetadataItem(is_empty=True)
