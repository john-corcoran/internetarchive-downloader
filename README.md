# Internet Archive Downloader

This Python script uses multithreading and multiprocessing in conjunction with the [Internet Archive Python Library](https://archive.org/services/docs/api/internetarchive/) to provide bulk downloads of files associated with Internet Archive ([archive.org](https://archive.org/)) items and collections, with optional interrupted download resumption and file hash verification. Wayback Machine ([web.archive.org](https://web.archive.org/)) pages are not supported by this script.

## Getting started

### Prerequisites

Python 3.7 or later is required, with the Internet Archive Python Library installed ([Internet Archive Python Library installation instructions](https://archive.org/services/docs/api/internetarchive/installation.html)).

This script has been tested with macOS 11.6 (using Python >= 3.7 installed using [Homebrew](https://brew.sh/)), Ubuntu 20.04, and Windows 10 20H2.

### Download options

You can download individual Internet Archive item(s), and/or all items returned from an [archive.org search](https://archive.org/advancedsearch.php). An item is [defined within Internet Archive documentation](https://archive.org/services/docs/api/items.html) as:

> Archive.org is made up of “items”. An item is a logical “thing” that we represent on one web page on archive.org. An item can be considered as a group of files ... an item can be a book, a song, an album, a dataset, a movie, an image or set of images, etc.

#### Downloading individual Internet Archive item(s)

Downloading items individually requires finding the item's unique identifier. [Here is an example of a details page for an Internet Archive item](https://archive.org/details/gov.archives.arc.1155023) - in this example, the item identifier to use with this script is 'gov.archives.arc.1155023' (as listed in the URL, and by the 'Identifier' string on the item's details page).

#### Downloading items returned from a search term

Various item metadata fields can be searched, enabling flexible download options - such as downloading all items associated with a collection, and/or uploaded by a particular creator. A full list of fields is provided on the [archive.org advanced search page](https://archive.org/advancedsearch.php): it is recommended that the search term is built on the advanced search page, and after hitting the 'Search' button, the completed query can be copied across as an argument for this script.

## Responsible usage

Internet Archive is a non-profit organisation that is experiencing unprecedented service demand. Please consider [making a donation](https://archive.org/donate). Use of this script will impact the bandwidth available to other users; please use this script responsibly and do not exceed reasonable download quotas.

## Script usage

The script has two usage modes, outlined below. For either mode, info/warning/error messages will be written to the console and to log files, by default created in folder `ia_downloader_logs` (folder location may be modified using flag `-l` or `--logfolder`, e.g. `python3 main.py -l custom_log_folder`).

### Download

This is the primary usage mode, allowing download of files associated with Internet Archive item identifier(s).

Syntax:

    python3 main.py download -i [identifiers ...] -s ["search terms"] -o output_folder [flags]

Usage example:

    python main.py download -i gov.archives.arc.1155023 TourTheInternationalSpaceStation -s "collection:(nasa) AND date:1975-11-13" -o space_videos

The above will `download` all files associated with Internet Archive items with identifiers `gov.archives.arc.1155023`, `TourTheInternationalSpaceStation`, and the results of search term `"collection:(nasa) AND date:1975-11-13"`, to folder `space_videos`.

The available flags can be viewed using: `python3 ia_downloader.py download --help`, and are as follows:

- `-i [str ... str]` or `--identifiers [str ... str]`: Internet Archive item identifiers to download (see section above for where to find identifier strings on archive.org item pages).
- `-s ["str" ... "str"]` or `--search ["str" ... "str"]`: search terms for which all returned Internet Archive items will be downloaded. Recommend building the search term using the [archive.org advanced search page](https://archive.org/advancedsearch.php). Use quotes to encapsulate each search term - Windows may be fussy with needing quote characters to be escaped, but try using brackets within your search rather than quotes to avoid this issue, e.g. `-s "creator:(National Archives and Records Administration) AND collection:(newsandpublicaffairs)"`.
- `-o [str]` or `--output [str]`: output folder to store downloaded files in. If unspecified, default of `internet_archive_downloads` will be used.
- `-t [int]` or `--threads [int]`: number of download threads (i.e. how many file downloads to perform simultaneously). The maximum is `5`, which is also the default if left unspecified.
- `-v` or `--verify`: if used, as each download completes, an MD5 hash verification will be performed against the downloaded data and compared against the hash values listed in Internet Archive metadata. This provides confirmation that the file download completed successfully, and is recommended for large or interrupted/resumed file transfers. If you wanted to verify data in this way but forgot to use this flag, you can use the `verify` usage mode (detailed below) after the download completes.
- `-r` or `--resume`: if used, interrupted file transfers will be restarted where they left off, rather than being started over from scratch. In testing, Internet Archive connections can be unstable, so this is recommended for large file transfers.
- `--split [int]`: if used, the behaviour of downloads will change - instead of multiple files being downloaded simultaneously, only one file will be downloaded at a time, with each file over 10MB split into separate download threads (number of download threads is specified with this flag); each thread will download a separate portion of the file, and the file will be combined when all download threads complete. This may increase per-file download speeds, but will use more temporary storage space as files are downloaded. To avoid overloading Internet Archive servers, only one file will be downloaded at a time if this option is used (i.e. `-t` will be ignored). If using `-r` and the script has been restarted, use the same number of splits passed with this argument as was used during previous script execution. The maximum is `5`; the default is `1` (i.e. no file splitting will be performed).
- `-f [str ... str]` or `--filefilters [str ... str]`: one or more (space separated) file name filters; only files with names that contain any of the provided filter strings (case insensitive) will be downloaded. If multiple filters are provided, the search will be an 'OR' (i.e. only one of the provided strings needs to hit). For example, `-f png jpg` will download all files that contain either `png` or `jpg` in the file name. Individual terms can be wrapped in quotation marks.
- `--invertfilefiltering`: when used with `filefilters` above, files matching the provided filter strings (case insensitive) will be excluded from download.
- `-c [str] [str]` or `--credentials [str] [str]`: some Internet Archive items contain files that can only be accessed when logged in with an Internet Archive account. An email address and password can be supplied with this argument as two separate strings (email address first, then password - note that passwords containing spaces will need to be wrapped in quotation marks). Note that terminal history on your system may reveal your credentials to other users, and your credentials will be stored in a plaintext file in either `$HOME/.ia` or `$HOME/.config/ia.ini` as per [Internet Archive Python Library guidance](https://archive.org/services/docs/api/internetarchive/api.html#configuration). Credentials will be cached for future uses of this script (i.e. this flag only needs to be used once). Note that, if the Internet Archive item is [access restricted (e.g. books in the lending program, or 'stream only' videos),](https://help.archive.org/hc/en-us/articles/360016398872-Downloading-A-Basic-Guide-) downloads will still not be possible even if credentials are supplied ('403 Forbidden' messages will occur).
- `--hashfile [str]`: output path to write file containing hash metadata (as recorded by Internet Archive). If left unspecified, the hash metadata file will be created in the cache within the logs folder.
- `--cacherefresh`: metadata for Internet Archive items and collections will be cached in the log folder and used if a download is resumed or restarted, or if the `verify` mode is used. When downloading, metadata will be refreshed if the data in the cache is over one week old, or if this flag is used.

Usage example incorporating flags:

    python3 ia_downloader.py download -i gov.archives.arc.1155023 -s "collection:(nasa) AND date:1975-11-13" -o space_videos -t 3 -v -r -f mpeg mp4 -c user@email.com Passw0rd --hashfile ia_metadata.txt

### Verify

This usage mode provides confirmation that a previous download session using this script completed successfully, and that all downloaded files match the MD5 hash values as reported by Internet Archive.

Syntax:

    python3 ia_downloader.py verify data_folder [data_folder ...] [flags]

Usage example:

    python3 ia_downloader.py verify space_videos

The above will `verify` that the Internet Archive hash metadata (cached during a previous download session and stored in the logs folder) aligns with hash values that will be calculated by the script for the files as previously downloaded in folder `space_videos`.

The available flags can be viewed using: `python3 ia_downloader.py verify --help`, and are as follows:

- `-i [str ... str]` or `--identifiers [str ... str]`: if only certain Internet Archive item folders are to be verified in your data folder, one or more may be specified with this flag (space separated).
- `--hashfile [str]`: by default, the verification process will be performed using metadata cached during previous script execution, as stored in the logs folder. This flag may be used to specify an alternate location for the hash metadata file to be used during verification.
- `-f [str ... str]` or `--filefilters [str ... str]`: one or more (space separated) file name filters; use this flag to replicate any file filters specified during the original download, so that warnings are not generated for files that are intentionally filtered from the original Internet Archive item.
- `--invertfilefiltering`: when used with `filefilters` above, files matching the provided filter strings (case insensitive) will be excluded from verification.
- `--nopaths`: if the files have been moved from their original locations, then using this flag will instruct the script to only check that the hash values listed in the Internet Archive metadata reside somewhere in the download folder, rather than additionally checking that they are in the expected relative locations. This should still be fine for most use cases, but would not report on edge cases such as duplicate copies of a file with the same hash value having been deleted. It is likely that `--hashfile` will need to be used with this option, as if folder structure for the downloaded files has changed, it will not be possible to find associated metadata within the cache.

Usage example incorporating flags:

    python3 ia_downloader.py verify space_videos -i gov.archives.arc.1155023 --hashfile space_videos/20210601_155025_ia_downloader_hashes.txt -f mpeg mp4

## Privacy, log data, and uninstallation

This script only shares data with the Internet Archive to facilitate file downloads. No other third party services are communicated with.

Log data and cached Internet Archive metadata is stored by default in folder `ia_downloader_logs` (created in the folder that the script is executed in). Logs capture system details (including Python version and operating system), command line arguments used, and events occurring during script execution. Credentials are not recorded in these logs, but will be retained on the local system in terminal history and in a plaintext file in either `$HOME/.ia` or `$HOME/.config/ia.ini` as per [Internet Archive Python Library guidance](https://archive.org/services/docs/api/internetarchive/api.html#configuration).

Full uninstallation can be achieved by:

1. Deleting the script and any other downloaded files (e.g. the readme and license).
2. Deleting the logs folder (`ia_downloader_logs` by default).
3. If desired, removing records of Internet Archive credentials stored in terminal history or in folders listed above.
4. If desired, removing the Internet Archive Python Library and Python runtime.

## Known issues

1. Each Internet Archive item has an `[identifier]_files.xml` file containing Internet Archive metadata. This file is not assessed during verification processes, as in testing it was found that the hash value of the downloaded file does not always match the value listed in Internet Archive metadata.
2. Regular disconnects may occur while downloading files from some Internet Archive items. This may be due to load on Internet Archive servers for popular items. Use of the `-r` flag will allow files to be resumed if disconnects occur.
3. A [Python bug](https://bugs.python.org/issue38428) may cause issues in Windows when trying to quit the script using `CTRL+C`. A `SIGBREAK` can be sent instead using `CTRL+BREAK`, or by invoking the on-screen keyboard (`WIN+R`, then run `osk.exe`) and using its `Ctrl+ScrLk` keys.

## Contributing

If you would like to contribute, please fork the repository and use a feature branch. Pull requests are warmly welcome.

## Licensing

The code in this project is licensed under the MIT License.
