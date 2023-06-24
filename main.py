import os
import sys
import datetime
import argparse
import pathlib
import platform
import internetarchive
from src.download import download
from src.log import check_argument_int_greater_than_one, prepare_logging
from ia_downloader import verify, get_identifiers_from_search_term

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

            if args.hashfile:
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
                "Script complete; %s warnings/errors occurred requiring review (see log entries"
                " above, replicated in folder '%s')",
                counter_handler.count['WARNING'] + counter_handler.count['ERROR'],
                args.logfolder
            )
        else:
            log.info("Script complete; no errors reported")

    except KeyboardInterrupt:
        log.warning(
            "KeyboardInterrupt received, quitting immediately (any in-progress downloads or"
            " verifications have been terminated)"
        )
    except Exception as error:
        log.exception("Exception occurred: %s", error)


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
