import os
from multiprocessing.pool import ThreadPool
from datetime import datetime
import logging
from src.ia_downloader import file_paths_in_folder, verify, bytes_filesize_to_readable_str, file_download
from src.item_metadata import MetadataItem


class DownloadQueue:

    def __init__(
        self,
        item: MetadataItem,
        cache_folder,
        identifier,
        log: logging.Logger,
        file_filters=None,
        invert_file_filtering=False,
        hash_file=None,
        output_folder=None,
        hash_pool=None,
        resume_flag: bool = None,
        split_count=None,
        logfolder=None
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
        self.item = item
        self.cache_folder = cache_folder
        self.identifier = identifier
        self.log = log
        self.file_filters = file_filters
        self.invert_file_filtering = invert_file_filtering
        self.hash_file = hash_file
        self.output_folder = output_folder
        self.hash_pool = hash_pool
        self.resume_flag = resume_flag
        self.split_count = split_count
        self.logfolder = logfolder

        self.item_file_count = len(self.item.item_metadata["files"])
        item_total_size = 0
        item_filtered_files_size = 0
        self.download_queue = []

        # If the 'item' is our custom CacheDict, then we built it from cache - so don't need to
        # write another metadata file
        metadata_folder = os.path.join(
            cache_folder,
            f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{identifier}_metadata.txt"
        )

        for file in self.item.item_metadata["files"]:
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
            log_write_str = f"{identifier}|{file['name']}|{file['size']}|{file['md5']}|{file['mtime']}\n"
            if self.item.is_empty:
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

            self.download_queue.append(
                DownloadJob(
                    identifier,
                    file["name"],
                    int(file["size"]),
                    file["md5"],
                    int(file["mtime"]),
                    split_count
                )
            )

        self.item_total_size = item_total_size
        self.item_filtered_files_size = item_filtered_files_size

    def process(self, thread_count):
        identifier_output_folder = os.path.join(self.output_folder, self.identifier)
        if os.path.isdir(identifier_output_folder) and len(file_paths_in_folder(identifier_output_folder)) > 0:
            size_verification = verify(
                hash_file=None,
                data_folders=[self.output_folder],
                no_paths_flag=False,
                hash_flag=False,
                cache_parent_folder=os.path.join(self.logfolder, "cache"),
                identifiers=[self.identifier],
                file_filters=self.file_filters,
                invert_file_filtering=self.invert_file_filtering,
                quiet=True,
            )
            if size_verification:
                self.log.info(
                    "'%s' appears to have been fully downloaded in folder '%s' - skipping",
                    self.identifier, self.output_folder
                )
                return

        if self.file_filters is not None:
            if not self.invert_file_filtering:
                if len(self.download_queue) > 0:
                    self.log.info(
                        "%d files (%s) match file filter(s) '%s' (case insensitive) and will be"
                        " downloaded (out of a total of %d files (%s) available)",
                        len( self.download_queue),
                        bytes_filesize_to_readable_str(self.item_filtered_files_size),
                        " ".join(self.file_filters),
                        self.item_file_count,
                        bytes_filesize_to_readable_str(self.item_total_size)
                    )
                else:
                    self.log.info(
                        "No files match the filter(s) '%s' in item '%s' - no downloads will be"
                        " performed",
                        " ".join(self.file_filters), self.identifier
                    )
                    return
            else:
                if len(self.download_queue) > 0:
                    self.log.info(
                        "%d files (%s) NOT matching file filter(s) '%s' (case insensitive) will"
                        " be downloaded (out of a total of %d files (%s) available)",
                        len(self.download_queue),
                        bytes_filesize_to_readable_str(self.item_filtered_files_size),
                        " ".join(self.file_filters),
                        self.item_file_count,
                        bytes_filesize_to_readable_str(self.item_total_size)
                    )
                else:
                    self.log.info(
                        "All files are excluded by filter(s) '%s' in item '%s' - no downloads"
                        " will be performed",
                        " ".join(self.file_filters), self.identifier
                    )
                    return
        else:
            self.log.info(
                "'%s' contains %d files (%s)",
                self.identifier,
                len(self.download_queue),
                bytes_filesize_to_readable_str(self.item_total_size)
            )

        with ThreadPool(thread_count) as download_pool:
            download_detail_list = [(
                job.identifier,
                job.ia_file_name,
                job.ia_file_size,
                job.ia_md5,
                job.ia_mtime,
                self.output_folder,
                job.hash_pool,
                self.resume_flag,
                job.split_count,
                job.bytes_range,
                job.chunk_number,
            ) for job in self.download_queue]
            download_pool.map(file_download, download_detail_list, chunksize=1)
            self.log.debug("Waiting for download pool to complete")
            download_pool.close()
            download_pool.join()

        self.log.info("Download phase complete for item '%s'", self.identifier)
        if self.hash_file is not None:
            self.hash_file.flush()
            os.fsync(self.hash_file.fileno())
        verify(
            hash_file=None,
            data_folders=[self.output_folder],
            no_paths_flag=False,
            hash_flag=False,
            cache_parent_folder=os.path.join(self.logfolder, "cache"),
            identifiers=[self.identifier],
            file_filters=self.file_filters,
            invert_file_filtering=self.invert_file_filtering,
        )


class DownloadJob:
    
    def __init__(
            self,
            identifier,
            name,
            file_size,
            md5,
            mtime,
            split_count
        ):
        self.identifier = identifier
        self.name = name
        self.file_size = file_size
        self.md5 = md5
        self.mtime = mtime
        self.split_count = split_count
