import argparse
from src.log import check_argument_int_greater_than_one


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
    )
)

subparsers = parser.add_subparsers(
    help=(
        "Either 'download' files associated with an Internet Archive identifier, or 'verify' a"
        " previously-completed download was successful and files match expected MD5 hash values"
    ),
    dest="command",
    required=True
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
    )
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
    )
)
download_parser.add_argument(
    "-o",
    "--output",
    type=str,
    default="internet_archive_downloads",
    help="Folder to download files to"
)
download_parser.add_argument(
    "-t",
    "--threads",
    type=check_argument_int_greater_than_one,
    default=5,
    help=(
        "Number of download threads (i.e. how many downloads to perform simultaneously)"
        " (default is 5)"
    )
)
download_parser.add_argument(
    "-v",
    "--verify",
    default=False,
    action="store_true",
    help="Perform an MD5 hash check on each file as downloads complete"
)
download_parser.add_argument(
    "-r",
    "--resume",
    default=False,
    action="store_true",
    help=(
        "Attempt to resume downloads using already-downloaded data if a connection error occurs"
    )
)
download_parser.add_argument(
    "--split",
    type=check_argument_int_greater_than_one,
    default=1,
    help=(
        "To increase per-file download speeds, split files above 10MB into provided number of"
        " chunks, and reconstruct on completion"
    )
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
    )
)
download_parser.add_argument(
    "--invertfilefiltering",
    default=False,
    action="store_true",
    help=(
        "Invert file filtering logic so that only files NOT matching filefilters will be"
        " downloaded"
    )
)
download_parser.add_argument(
    "-c",
    "--credentials",
    type=str,
    nargs=2,
    help=(
        "Email address and password (as separate strings) for Internet Archive account"
        " (required for download of some Internet Archive items)"
    )
)
download_parser.add_argument(
    "--hashfile",
    type=str,
    help=(
        "Output path to write file containing hash metadata to (if not specified, file will"
        " be created in the output folder)"
    )
)
download_parser.add_argument(
    "--cacherefresh",
    default=False,
    action="store_true",
    help="Flag to update any cached Internet Archive metadata from previous script executions"
)

verify_parser = subparsers.add_parser("verify")
verify_parser.add_argument(
    "data_folders",
    type=str,
    nargs="+",
    help="Path to folder containing previously downloaded data"
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
    )
)
verify_parser.add_argument(
    "--hashfile",
    type=str,
    help=(
        "Path to file containing hash metadata from previous download using this script (if not"
        " specified, cached data from previous script execution will be used)"
    )
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
    )
)
verify_parser.add_argument(
    "--invertfilefiltering",
    default=False,
    action="store_true",
    help=(
        "Invert file filtering logic so that only files NOT matching filefilters will be"
        " verified"
    )
)
verify_parser.add_argument(
    "--nopaths",
    default=False,
    action="store_true",
    help=(
        "If files are no longer in the same relative paths, perform lookup based only on"
        " whether MD5 hashes are present in the data set (rather than also checking where those"
        " files are stored)"
    )
)
