# Internet Archive Downloader

This script uses multithreading and multiprocessing in conjunction with the [Internet Archive Python Library](https://archive.org/services/docs/api/internetarchive/) to provide bulk downloads of files associated with Internet Archive ([archive.org](https://archive.org/)) items, with optional interrupted download resumption and file hash verification.

## Getting started

### Prerequisites

Python 3.7 or later is required, with the Internet Archive Python Library installed ([Internet Archive Python Library installation instructions](https://archive.org/services/docs/api/internetarchive/installation.html)).

This script has been tested with macOS 11.3 (using Python >= 3.7 installed using [Homebrew](https://brew.sh/)), Ubuntu 20.04, and Windows 10 20H2.

### Finding the Internet Archive item identifier(s)

Internet Archive items and item identifiers are [defined within Internet Archive documentation](https://archive.org/services/docs/api/items.html) as:

> Archive.org is made up of “items”. An item is a logical “thing” that we represent on one web page on archive.org. An item can be considered as a group of files ... an item can be a book, a song, an album, a dataset, a movie, an image or set of images, etc. Every item has an identifier that is unique across archive.org.

[Here is an example of a details page for an Internet Archive item](https://archive.org/details/gov.archives.arc.1155023) - in this example, the item identifier to use with this script is 'gov.archives.arc.1155023' (as listed in the URL, and by the 'Identifier' string on the item's details page).

## Responsible usage

Internet Archive is a non-profit organisation that is experiencing unprecedented service demand. Please consider [making a donation](https://archive.org/donate). Use of this script will impact the bandwidth available to other users; please use this script responsibly and do not exceed reasonable download quotas.

## Script usage

The script has two usage modes, outlined below. For either mode, info/warning/error messages will be written to the console and to log files, by default created in folder `ia_downloader_logs` (folder location may be modified using flag `-l` or `--logfolder`, e.g. `python3 ia_downloader.py -l custom_log_folder`).

### Download

This is the primary usage mode, allowing download of files associated with Internet Archive item identifier(s).

Syntax:

    python3 ia_downloader.py download identifiers [identifiers ...] output_folder [flags]

Usage example:

    python3 ia_downloader.py download gov.archives.arc.1155023 TourTheInternationalSpaceStation space_videos

The above will `download` all files associated with Internet Archive items with identifiers `gov.archives.arc.1155023` and `TourTheInternationalSpaceStation` to folder `space_videos`.

Internet Archive 'collections' (a special type of item that groups other items together, based on a theme) may also be specified as the identifier, using prefix `collection:`, e.g. `collection:nasa`. Each item within the collection will be downloaded in turn.

The available flags can be viewed using: `python3 ia_downloader.py download --help`, and are as follows:

- `-t [int]` or `--threads [int]`: number of download threads (i.e. how many file downloads to perform simultaneously). The maximum is `5`, which is also the default if left unspecified.
- `-v` or `--verify`: if used, as each download completes, an MD5 hash verification will be performed against the downloaded data and compared against the hash values listed in Internet Archive metadata. This provides confirmation that the file download completed successfully, and is recommended for large or interrupted/resumed file transfers. If you wanted to verify data in this way but forgot to use this flag, you can use the `verify` usage mode (detailed below) after the download completes.
- `-r` or `--resume`: if used, interrupted file transfers will be restarted where they left off, rather than being started over from scratch. In testing, Internet Archive connections can be unstable, so this is recommended for large file transfers. This is marked as 'experimental' as the download process deviates from the core Internet Archive Python Library, and therefore may break in future updates.
- `-s [int]` or `--split [int]`: if used, the behaviour of downloads will change - instead of multiple files being downloaded simultaneously, only one file will be downloaded at a time, with each file over 10MB split into separate download threads (number of download threads is specified with this flag); each thread will download a separate portion of the file, and the file will be combined when all download threads complete. This may increase per-file download speeds, but will use more temporary storage space as files are downloaded. As above, this is considered experimental. To avoid overloading Internet Archive servers, only one file will be downloaded at a time if this option is used (i.e. `-t` will be ignored). If using `-r` and the script has been restarted, use the same number of splits passed with this argument as was used during previous script execution. The maximum is `5`; the default is `1` (i.e. no file splitting will be performed).
- `-f [str ... str]` or `--filefilters [str ... str]`: one or more (space separated) file name filters; only files with names that contain any of the provided filter strings (case insensitive) will be downloaded. If multiple filters are provided, the search will be an 'OR' (i.e. only one of the provided strings needs to hit). For example, `-f png jpg` will download all files that contain either `png` or `jpg` in the file name. Individual terms can be wrapped in quotation marks.
- `--hashfile [str]`: output path to write file containing hash metadata (as recorded by Internet Archive). If left unspecified, the hash metadata file will be created in the output folder.

Usage example incorporating flags:

    python3 ia_downloader.py download gov.archives.arc.1155023 space_videos -t 3 -v -r -f mpeg mp4 --hashfile ia_metadata.txt

### Verify

This usage mode provides confirmation that a previous download session using this script completed successfully, and that all downloaded files match the MD5 hash values as reported by Internet Archive.

Syntax:

    python3 ia_downloader.py verify hashfile data_folder [--nopaths]

Usage example:

    python3 ia_downloader.py verify space_videos/20210601_155025_ia_downloader_hashes.txt space_videos

The above will `verify` that the Internet Archive hash metadata (written during a previous download session) in file `space_videos/20210601_155025_ia_downloader_hashes.txt` aligns with hash values that will be calculated by the script for the files as previously downloaded in folder `space_videos`.

The available flag can be viewed using: `python3 ia_downloader.py verify --help`, and is as follows:

- `--nopaths`: if the files have been moved from their original locations, then using this flag will instruct the script to only check that the hash values listed in the Internet Archive metadata reside somewhere in the download folder, rather than additionally checking that they are in the expected relative locations. This should still be fine for most use cases, but would not report on edge cases such as duplicate copies of a file with the same hash value having been deleted.

## Known issues

1. Each Internet Archive item has an `[identifier]_files.xml` file containing Internet Archive metadata. This file is not assessed during verification processes, as in testing it was found that the hash value of the downloaded file does not always match the value listed in Internet Archive metadata.
2. A [Python bug](https://bugs.python.org/issue38428) may cause issues in Windows when trying to quit the script using `CTRL+C`. A `SIGBREAK` can be sent instead using `CTRL+BREAK`, or by invoking the on-screen keyboard (`WIN+R`, then run `osk.exe`) and using its `Ctrl+ScrLk` keys.

## Contributing

If you would like to contribute, please fork the repository and use a feature branch. Pull requests are warmly welcome.

## Licensing

The code in this project is licensed under the MIT License.
