import os
import sys
import datetime
import pathlib
import platform
import internetarchive
from src.config import ConfigArgs
from src.download import download
from src.log import prepare_logging
from src.ia_downloader import verify, get_identifiers_from_search_term
#from src.argument_parser import parser


def main() -> None:
    """Captures args via argparse and sets up either downloading threads or verification check"""
    run_time = datetime.datetime.now()
    datetime_string = run_time.strftime("%Y%m%d_%H%M%S")

    args = ConfigArgs()
    #args = parser.parse_args()

    # Set up logging
    for log_subfolder in ["logs", "cache"]:
        pathlib.Path(os.path.join(args.logfolder, log_subfolder)).mkdir(parents=True, exist_ok=True)
    log, counter_handler = prepare_logging(
        datetime_string,
        os.path.join(args.logfolder, "logs"),
        "ia_downloader",
        args,
    )
    if args.filefilters is None and args.invertfilefiltering:
        log.warning("--invertfilefiltering flag will be ignored as no file filters were provided")
    log.info(
        "Internet Archive is a non-profit organisation that is experiencing unprecedented service"
        " demand. Please consider making a donation: https://archive.org/donate"
    )
    log.info("Logs will be stored in folder '%s'", args.logfolder)

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
                "Internet Archive metadata will be written to hash file at '%s'",
                args.hashfile
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
            hashfile_file_handler = open(args.hashfile, "w", encoding="UTF-8")
        identifiers = args.identifiers if args.identifiers is not None else []
        if args.search:
            for search in args.search:
                identifiers.extend(
                    get_identifiers_from_search_term(
                        search=search,
                        cache_parent_folder=os.path.join(args.logfolder, "cache"),
                        cache_refresh=args.cacherefresh,
                    )
                )
        for identifier in identifiers:
            download(
                identifier=identifier,
                output_folder=os.path.join("output", args.output_folder),
                hash_file=hashfile_file_handler,
                thread_count=args.threads,
                resume_flag=args.resume,
                verify_flag=args.verify,
                split_count=args.split,
                file_filters=args.filefilters,
                invert_file_filtering=args.invertfilefiltering,
                cache_parent_folder=os.path.join(args.logfolder, "cache"),
                cache_refresh=args.cacherefresh,
                logfolder=args.logfolder
            )

        if args.hashfile:
            hashfile_file_handler.close()

    if args.command == "verify":
        verify(
            hash_file=args.hashfile,
            data_folders=args.data_folders,
            no_paths_flag=args.nopaths,
            hash_flag=True,
            cache_parent_folder=os.path.join(args.logfolder, "cache"),
            identifiers=args.identifiers,
            file_filters=args.filefilters,
            invert_file_filtering=args.invertfilefiltering,
        )

    if counter_handler.count["WARNING"] > 0 or counter_handler.count["ERROR"] > 0:
        log.warning(
            "Script complete; %d warnings/errors occurred requiring review (see log entries"
            " above, replicated in folder '%s')",
            counter_handler.count['WARNING'] + counter_handler.count['ERROR'],
            args.logfolder
        )
    else:
        log.info("Script complete; no errors reported")


if __name__ == "__main__":
    # Entry point when running script directly
    python_major, python_minor = platform.python_version_tuple()[0:2]
    if int(python_major) < 3 or int(python_minor) < 7:
        print(
            ("Please use Python 3.7 or above "
             f"(version currently installed is {platform.python_version()})")
        )
        sys.exit()

    main()
