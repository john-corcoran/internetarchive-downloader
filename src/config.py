import yaml

class ConfigArgs:

    allowed_args = [
        "command",
        "logfolder",
        "identifiers",
        "search",
        "threads",
        "verify",
        "split",
        "filefilters",
        "invertfilefiltering",
        "credentials",
        "hashfile",
        "cacherefresh",
        "data_folders",
        "nopaths",
        "output_folder",
        "resume"
    ]
    command = "download"
    logfolder = "ia_downloader_logs"
    identifiers = None
    search = ""
    threads = 5
    verify = False
    split = 1
    filefilters = None
    invertfilefiltering = False
    credentials = None
    hashfile = None
    cacherefresh = False
    data_folders = None
    nopaths = False
    output_folder = "output"
    resume = False

    def __init__(self):
        with open("config/config.yaml", "r", encoding="UTF-8") as config_file:
            args = yaml.safe_load(config_file)

        self._verify_args(args)

        for key, value in args.items():
            if key in self.allowed_args:
                if value is not None:
                    setattr(self, key, value)
            else:
                print(f"Warning: Key '{key}' not allowed and will not be set.")

    def _check_missing_args(self, args):
        if self.command == "download":
            self._check_missing_args_download(args)
        if self.command == "verify":
            self._check_missing_args_verify(args)

    def _check_missing_args_download(self, args):
        obligatory_args = [
            "identifiers"
        ]
        for obligatory_arg in obligatory_args:
            if not obligatory_arg in args.keys():
                raise ValueError(f"Argument {obligatory_arg} is not supplied in the config file!")

    def _check_missing_args_verify(self, args):
        obligatory_args = [
            "identifiers"
        ]
        for obligatory_arg in obligatory_args:
            if not obligatory_arg in args.keys():
                raise ValueError(f"Argument {obligatory_arg} is not supplied in the config file!")

    def _check_arg_values(self, args):
        #error_message = "Argument %s has received illegal value %s!"
        assert (args["command"] in ["download", "verify"])
        assert isinstance(args["logfolder"], str)
        assert len(args["identifiers"]) > 0
        assert isinstance(args["identifiers"], list)
        assert all(isinstance(identifier, str) for identifier in args["identifiers"])
        assert (args["credentials"] is None or len(args) == 2)
        #TODO

    def _verify_args(self, args):
        self._check_missing_args(args)
        self._check_arg_values(args)

    def __contains__(self, item):
        return hasattr(self, item) and self.__getattribute__(item) is not None
