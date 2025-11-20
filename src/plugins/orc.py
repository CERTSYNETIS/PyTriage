import os
import re
import time
import json
import subprocess
from re import compile
from src.thirdparty import triageutils as triageutils
from src.thirdparty.ParseEVTX import ParseEVTX
from src.thirdparty.ParseRegistry import ParseRegistry
from src.thirdparty.ParsePrefetch import ParsePrefetch
from src.thirdparty.ParseMFT.mft_analyzer import MftAnalyzer
from src.thirdparty.ParseMPLog import ParseMPLog
from src.thirdparty.winactivities.ParseWinactivities import ParseWinActivities
from src.thirdparty.wrapper_docker import WrapperDocker
from src.thirdparty.trashparse.ParseTrash import TrashParse
from src.thirdparty.ParseRDPCache import BMCContainer
from src.thirdparty.ParseLnk import ParseLnk
from src.thirdparty.ParseJumpList import ParseJumpList
from src.thirdparty.ParseTask import ParseTask
from src.thirdparty.ParseWebCache import ParseWebcache
from logging import Logger
from pathlib import Path
from src import BasePlugin, Status


class Plugin(BasePlugin):
    """
    Plugin pour triage de collecte générée par ORC
    """

    def __init__(self, conf: dict):
        super().__init__(config=conf)
        self._docker = WrapperDocker(logger=self.logger)
        self.input_archive = Path(
            os.path.join(self.upload_dir, conf["archive"]["name"])
        )
        self.private_key_file = Path(
            os.path.join(self.upload_dir, conf["run"]["orc"]["private_key_file"])
        )

        self.orc_dir = Path(os.path.join(self.upload_dir, self.hostname, "orc"))
        triageutils.create_directory_path(path=self.orc_dir, logger=self.logger)

        self.zip_destination = Path(os.path.join(self.orc_dir, "extract"))
        triageutils.create_directory_path(path=self.zip_destination, logger=self.logger)

        self.config["general"]["extracted_zip"] = f"{self.zip_destination}"
        self.update_config_file(data=self.config)

        self.parsed_share = Path(os.path.join(self.orc_dir, "pytriage_parsed_files"))
        triageutils.create_directory_path(path=self.parsed_share, logger=self.logger)

        self.plaso_folder = Path(os.path.join(self.parsed_share, "pytriage_plaso"))
        triageutils.create_directory_path(path=self.plaso_folder, logger=self.logger)

        self.hayabusa_folder = Path(os.path.join(self.parsed_share, "Hayabusa"))
        triageutils.create_directory_path(path=self.hayabusa_folder, logger=self.logger)

    @triageutils.LOG
    def rename_orc_file(
        self, filepath: Path, logger: Logger, LOGLEVEL: str = "NOLOG"
    ) -> bool:
        """
        Rename file by keeping only real file name
        logger and LOGLEVEL are used by LOG decorator

        Return:
            bool: true/false if success rename or not
        """
        try:
            _new_name = filepath.name
            _path = filepath.parent

            _pattern = re.compile(r"_\{.*\}.data$")
            if _pattern.search(_new_name):
                _new_name = re.sub(_pattern, "", _new_name)

            _pattern = re.compile(r"^[A-Fa-f0-9]+_[A-Fa-f0-9]+_[A-Fa-f0-9]+_[0-9]{1}_")
            if _pattern.search(_new_name):
                _new_name = re.sub(_pattern, "", _new_name)

            _new_path = Path(_path) / Path(_new_name)

            if triageutils.file_exists(file=_new_path, LOGLEVEL="NOLOG"):
                # self.info(f"[rename_orc_file] File exists !")
                _parent = Path(_path) / Path(str(round(time.time() * 1000)))
                triageutils.create_directory_path(path=_parent, LOGLEVEL="NOLOG")
                _new_path = _parent / Path(_new_name).name
            triageutils.move_file(
                src=filepath, dst=_new_path, logger=self.logger, LOGLEVEL="NOLOG"
            )
            return True
        except Exception as ex:
            self.error(f"[rename_orc_file] {ex}")
            return False

    @triageutils.LOG
    def extract_orc_archive(self, archive: Path, dest: Path, logger: Logger):
        try:
            if archive.name.endswith(".7z.p7b"):
                res, _decrypted_archive = triageutils.decrypt_orc_archive(
                    archive=archive,
                    dest=dest,
                    private_key=self.private_key_file,
                    logger=self.logger,
                )
                if not res:
                    raise Exception("Error in decrypt ORC archive")
            else:
                _decrypted_archive = archive
            if _decrypted_archive.name.endswith(".7z"):
                res = triageutils.extract_7z_archive(
                    archive=_decrypted_archive, dest=dest, logger=self.logger
                )
                self.logger.info(f"[extract_orc_archive] extract_7z_archive: {res}")
            else:
                raise Exception("Not a valid 7z ORC archive")
        except Exception as ex:
            self.logger.error(f"[extract_orc_archive] {ex}")
            raise ex

    @triageutils.LOG
    def extract_all_7z(self, logger: Logger):
        try:
            for _7z in triageutils.search_files_by_extension_generator(
                src=self.zip_destination, extension=".7z", logger=self.logger
            ):
                _extract_to = self.orc_dir / Path(_7z.stem)
                if triageutils.directory_exists(
                    dir=_extract_to.as_posix(), logger=self.logger
                ):
                    triageutils.delete_directory(src=_extract_to, logger=self.logger)
                res = triageutils.extract_7z_archive(
                    archive=_7z, dest=_extract_to, logger=self.logger
                )
            for _file in triageutils.search_files_by_extension_generator(
                src=self.orc_dir, extension=".data", logger=self.logger
            ):
                self.rename_orc_file(
                    filepath=_file, logger=self.logger, LOGLEVEL="NOLOG"
                )
        except Exception as ex:
            self.error(f"[extract_all_7z] {str(ex)}")

    @triageutils.LOG
    def orc_evtx_winlogbeat(self, logger: Logger):
        try:
            win_log_path = os.path.join(self.winlogbeat, self.clientname, self.hostname)
            triageutils.create_directory_path(path=win_log_path, logger=self.logger)
            for _f in self.orc_dir.rglob("*.evtx"):
                if _f.is_file():
                    triageutils.copy_file(
                        src=_f, dst=win_log_path, overwrite=True, logger=None
                    )
        except Exception as ex:
            self.error(f"[orc_evtx_winlogbeat] {ex}")
            raise ex

    @triageutils.LOG
    def orc_parse_evtx(self, logger: Logger):
        try:
            _ip = self.logstash_url
            if _ip.startswith("http"):
                _ip = self.logstash_url.split("//")[1]
            evtx_parsed_share = self.parsed_share / "EVTX_parsed"
            triageutils.create_directory_path(
                path=evtx_parsed_share, logger=self.logger
            )
            for _f in self.orc_dir.rglob("*.evtx"):
                if _f.is_file():
                    _p = ParseEVTX(
                        evtxfilepath=_f,
                        ip=_ip,
                        port=self.evtxparser_port,
                        client=self.clientname,
                        hostname=self.hostname,
                        mapping=self.evtx_mapping,
                        output_folder=evtx_parsed_share,
                        logstash_is_active=self.is_logstash_active,
                        logger=self.logger,
                    )
                    self.info(f"[orc_parse_evtx] Parse: {_f}")
                    _res = _p.parse_evtx()
                    self.info(f"[orc_parse_evtx] Result: {_res}")
                    # send analytics info
                    if self.is_logstash_active:
                        _file_infos = triageutils.get_file_informations(filepath=_f)
                        _analytics = triageutils.generate_analytics(logger=self.logger)
                        _analytics["log"]["file"]["eventcount"] = _res.setdefault(
                            "nb_events_read", 0
                        )
                        _analytics["log"]["file"]["eventsent"] = _res.setdefault(
                            "nb_events_sent", 0
                        )
                        _analytics["log"]["file"]["path"] = str(_f)
                        _analytics["log"]["file"]["size"] = _file_infos.setdefault(
                            "fileSize", 0
                        )
                        _analytics["log"]["file"]["lastaccessed"] = (
                            _file_infos.setdefault("lastAccessTime", 0)
                        )
                        _analytics["log"]["file"]["creation"] = _file_infos.setdefault(
                            "creationTime", 0
                        )
                        _analytics["csirt"]["client"] = self.clientname
                        _analytics["csirt"]["hostname"] = self.hostname
                        _analytics["csirt"]["application"] = "orc_parse_evtx"
                        triageutils.send_data_to_elk(
                            data=_analytics,
                            ip=_ip,
                            port=self.selfassessment_port,
                            logger=self.logger,
                        )
        except Exception as ex:
            self.error(f"[orc_parse_evtx] {str(ex)}")
            raise ex

    @triageutils.LOG
    def orc_parse_registry(self, logger: Logger):
        try:
            # _reg_files = self.get_registry_files(logger=self.logger)
            _reg_share = self.parsed_share / "REGISTRY_parsed"
            triageutils.create_directory_path(path=_reg_share, logger=self.logger)
            _parse_reg = ParseRegistry(logger=self.logger)
            _parse_reg.parse_all(dir_to_reg=self.orc_dir, out_folder=_reg_share)
        except Exception as ex:
            self.error(f"[orc_parse_registry] {str(ex)}")
            raise ex

    @triageutils.LOG
    def orc_parse_mft(self, logger: Logger):
        try:
            _mft_files = triageutils.search_files(
                src=self.orc_dir, pattern="$MFT", strict=True
            )
            if len(_mft_files):
                _output_file = f"{self.parsed_share}/mft_parsed.csv"
                _mft = _mft_files[0]
                _analyzer = MftAnalyzer(
                    mft_file=_mft, output_file=_output_file, logger=self.logger
                )
                _analyzer.analyze()
            else:
                self.logger.error(f"[orc_parse_mft] No $MFT found")
        except Exception as ex:
            self.error(f"[orc_parse_mft] {str(ex)}")
            raise ex

    @triageutils.LOG
    def orc_parse_usn(self, logger: Logger):
        try:
            records = list()
            _usnfodler = self.orc_dir / "USNInfo"
            records = triageutils.search_files(
                src=_usnfodler, pattern="USNInfo", logger=self.logger
            )
            if len(records):
                _usn_share = self.parsed_share / "USN_parsed"
                triageutils.create_directory_path(path=_usn_share, logger=self.logger)
                triageutils.copy_files(src=records, dst=_usn_share, logger=self.logger)
        except Exception as ex:
            self.error(f"[orc_parse_usn] {str(ex)}")

    @triageutils.LOG
    def orc_parse_prefetch(self, logger: Logger):
        try:
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "*.pf".lower()
            )
            _prefetch_share = self.parsed_share / "Prefetch_parsed"
            triageutils.create_directory_path(path=_prefetch_share, logger=self.logger)
            for _f in self.orc_dir.rglob(_searchpattern):
                if _f.is_file():
                    _output_file = _prefetch_share / f"{_f.name}.json"
                    _analyzer = ParsePrefetch(
                        prefetch=_f,
                        output=_output_file,
                        logger=self.logger,
                    )
                    _analyzer.analyze()
        except Exception as ex:
            self.error(f"[orc_parse_prefetch] {str(ex)}")
            raise ex

    @triageutils.LOG
    def orc_parse_mplog(self, logger: Logger):
        try:
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "MPLog-*.log".lower()
            )
            _mplog_share = self.parsed_share / "MPLog_parsed"
            triageutils.create_directory_path(path=_mplog_share, logger=self.logger)
            for _f in self.orc_dir.rglob(_searchpattern):
                self.info(f"[orc_parse_mplog] Parse: {_f}")
                _analyzer = ParseMPLog(mplog_file=_f, output_directory=_mplog_share)
                _analyzer.orchestrator()
        except Exception as ex:
            self.error(f"[orc_parse_mplog] {str(ex)}")
            raise ex

    @triageutils.LOG
    def orc_parse_activitiescache(self, logger: Logger):
        try:
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl,
                "ActivitiesCache.db".lower(),
            )
            activitiescache_share = self.parsed_share / "ActivitiesCache_parsed"
            triageutils.create_directory_path(path=activitiescache_share, logger=self.logger)
            for _f in self.orc_dir.rglob(_searchpattern):
                if _f.is_file():
                    self.info(f"[orc_parse_activitiescache] Parse: {_f}")
                    _analyzer = ParseWinActivities(
                        DBfilepath=_f,
                        output_folder=activitiescache_share,
                        logger=self.logger,
                    )
                    _analyzer.process()
        except Exception as ex:
            self.error(f"[orc_parse_activitiescache] {str(ex)}")
            raise ex

    @triageutils.LOG
    def orc_parse_recyclebin(self, logger: Logger):
        try:
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "$Recycle.Bin".lower()
            )
            recyclebin_dir = self.parsed_share / "RecycleBin_parsed"
            triageutils.create_directory_path(path=recyclebin_dir, logger=self.logger)
            for _recyclebin_folder in self.orc_dir.rglob(_searchpattern):
                for _dir in triageutils.list_directory_full_path(
                    src=_recyclebin_folder,
                    onlydirs=True,
                    logger=self.logger,
                ):
                    _dir = Path(_dir)
                    self.info(f"[orc_parse_recyclebin] Parse: {_dir}")
                    trash = TrashParse(recyclebin_folder=_dir, logger=self.logger)
                    trash.listfile()
                    trash.parsefile()
                    _output = recyclebin_dir / f"{_dir.name}.csv"
                    trash.write_csv(csv_file=_output)
                    _output = recyclebin_dir / f"{_dir.name}.jsonl"
                    trash.write_jsonl(jsonl_file=_output)
        except Exception as ex:
            self.error(f"[orc_parse_recyclebin] {ex}")

    @triageutils.LOG
    def orc_get_consolehost_history(self, logger: Logger):
        try:
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "ConsoleHost_history.txt".lower()
            )
            psreadline_dir = self.parsed_share / "PSReadline_parsed"
            triageutils.create_directory_path(path=psreadline_dir, logger=self.logger)
            for _f in self.orc_dir.rglob(_searchpattern):
                if _f.is_file():
                    self.info(f"[orc_get_consolehost_history] Parse: {_f}")
                    _dst = psreadline_dir / f"{time.time()}_{_f.name}"
                    triageutils.copy_file_strict(
                        src=_f, dst=_dst, logger=self.logger
                    )
        except Exception as ex:
            self.error(f"[orc_get_consolehost_history] {str(ex)}")
            raise ex

    @triageutils.LOG
    def orc_get_RDPCache(self, logger: Logger):
        try:
            # Get BMC files
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "Terminal Server Client/**/*.bmc".lower()
            )
            RDPCache_dir = self.parsed_share / "RDPCache_parsed"
            triageutils.create_directory_path(path=RDPCache_dir, logger=self.logger)
            for _f in self.orc_dir.rglob(_searchpattern):
                if _f.is_file():
                    _dst = RDPCache_dir / _f.name
                    triageutils.copy_file(
                        src=_f, dst=_dst, overwrite=True, logger=self.logger
                    )
            # Get BIN files
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "Terminal Server Client/**/*.bin".lower()
            )
            for _f in self.orc_dir.rglob(_searchpattern):
                if _f.is_file():
                    _dst = RDPCache_dir / _f.name
                    triageutils.copy_file(
                        src=_f, dst=_dst, overwrite=True, logger=self.logger
                    )
            # Exec parser on subdirectories
            for _d in [f for f in RDPCache_dir.iterdir() if f.is_dir()]:
                try:
                    _extract_folder = _d / "images_parsed"
                    triageutils.create_directory_path(path=_extract_folder, logger=None)
                    _bmcc = BMCContainer(logger=self.logger)
                    for _cache_file in [
                        _temp_file
                        for _temp_file in _d.iterdir()
                        if _temp_file.is_file()
                    ]:
                        try:
                            self.logger.info(
                                f"[orc_get_RDPCache] Processing file: {_cache_file}"
                            )
                            if _bmcc.b_import(_cache_file):
                                _bmcc.b_process()
                                _bmcc.b_export(_extract_folder)
                                _bmcc.b_flush()
                        except Exception as ex:
                            self.error(f"[bmcc #1] {str(ex)}")
                except Exception as ex:
                    self.error(f"[bmcc #2] {str(ex)}")
        except Exception as ex:
            self.error(f"[orc_get_RDPCache] {str(ex)}")
            raise ex

    @triageutils.LOG
    def orc_parse_lnk(self, logger: Logger):
        try:
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "*.lnk".lower()
            )
            lnk_dir = self.parsed_share / "LNK_parsed"
            triageutils.create_directory_path(path=lnk_dir, logger=self.logger)
            for _f in self.orc_dir.rglob(_searchpattern):
                if _f.is_file():
                    _output_file = lnk_dir / f"{_f.stem}.json"
                    _analyzer = ParseLnk(
                        lnk_file=_f,
                        output=_output_file,
                        logger=self.logger,
                    )
                    _analyzer.analyze()
        except Exception as ex:
            self.error(f"[orc_parse_lnk] {str(ex)}")
            raise ex

    @triageutils.LOG
    def orc_parse_jumplist(self, logger: Logger):
        try:
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl,
                "*.automaticDestinations-ms".lower(),
            )
            jumplist_dir = self.parsed_share / "JumpList_parsed"
            triageutils.create_directory_path(path=jumplist_dir, logger=self.logger)
            for _f in self.orc_dir.rglob(_searchpattern):
                if _f.is_file():
                    _output_file = jumplist_dir / f"{_f.name}.jsonl"
                    _analyzer = ParseJumpList(
                        input_file=_f,
                        output_file=_output_file,
                        logger=self.logger,
                    )
                    _analyzer.analyze_automatic_destinations()
            _searchpatterncustom = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "*.customDestinations-ms".lower()
            )
            for _f in self.orc_dir.rglob(_searchpatterncustom):
                if _f.is_file():
                    _output_file = jumplist_dir / f"{_f.name}.jsonl"
                    _analyzer = ParseJumpList(
                        input_file=_f,
                        output_file=_output_file,
                        logger=self.logger,
                    )
                    _analyzer.analyze_custom_destinations()
        except Exception as ex:
            self.error(f"[orc_parse_jumplist] {str(ex)}")
            raise ex

    @triageutils.LOG
    def orc_parse_tasks(self, logger: Logger):
        try:
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "Tasks/*".lower()
            )
            tasks_dir = self.parsed_share / "Tasks_parsed"
            triageutils.create_directory_path(path=tasks_dir, logger=self.logger)
            for _f in self.orc_dir.rglob(_searchpattern):
                if _f.is_file():
                    try:
                        _output_file = tasks_dir / f"{_f.name}.json"
                        if triageutils.file_exists(file=_output_file, logger=None):
                            triageutils.delete_file(src=_output_file, logger=None)
                        _analyzer = ParseTask(
                            task_file=_f,
                            result_jsonl_file=_output_file,
                            logger=self.logger,
                        )
                        _analyzer.analyze()
                    except Exception as ex:
                        self.error(str(ex))
        except Exception as ex:
            self.error(f"[orc_parse_tasks] {str(ex)}")
            raise ex

    @triageutils.LOG
    def orc_parse_webcache(self, logger: Logger):
        try:
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "WebCacheV01.dat".lower()
            )
            webcache_dir = self.parsed_share / "WebCache_parsed"
            triageutils.create_directory_path(path=webcache_dir, logger=self.logger)
            for _f in self.orc_dir.rglob(_searchpattern):
                if _f.is_file():
                    try:
                        _output_jsonl_file = (
                            webcache_dir / f"{time.time()}_{_f.stem}.jsonl"
                        )
                        _analyzer = ParseWebcache(
                            cache_file=_f,
                            result_jsonl_file=_output_jsonl_file,
                            logger=self.logger,
                        )
                        _analyzer.analyze()
                    except Exception as ex:
                        self.error(str(ex))
        except Exception as ex:
            self.error(f"[orc_parse_webcache] {str(ex)}")
            raise ex

    @triageutils.LOG
    def generate_plaso_timeline(self, logger: Logger) -> Path:
        """Génère la timeline PLASO.
        Args:

        Returns:

        """
        try:
            if triageutils.file_exists(
                file=f"{self.orc_dir}/{self.hostname}.plaso",
            ):
                triageutils.delete_file(
                    src=f"{self.orc_dir}/{self.hostname}.plaso",
                )
            cmd = [
                "log2timeline.py",
                "--storage_file",
                f"{self.orc_dir}/{self.hostname}.plaso",
                f"{self.orc_dir}",
            ]
            self._docker.image = f'{self.docker_images["plaso"]["image"]}:{self.docker_images["plaso"]["tag"]}'
            if not self._docker.is_image_present(name=self._docker.image):
                raise Exception("Image not present")
            self._docker.container = f"{self.uuid}-plaso"
            self._docker.volumes = [f"{self.data_volume}:/data"]
            self._docker.execute_cmd(cmd=cmd)

            s_file = self.plaso_folder / f"{self.hostname}.plaso"
            triageutils.move_file(
                src=os.path.join(self.orc_dir, f"{self.hostname}.plaso"),
                dst=s_file,
                logger=self.logger,
            )
            if self.is_timesketch_active:
                triageutils.import_timesketch(
                    timelinename=f"{self.hostname}_DISK",
                    file=s_file,
                    timesketch_id=self.timesketch_id,
                    logger=self.logger,
                )
            return s_file
        except Exception as ex:
            self.logger.error(f"[generate_plaso_timeline] {ex}")
            raise ex

    @triageutils.LOG
    def orc_exec_hayabusa(self, logger: Logger) -> Path:
        """
        Execute Hayabusa on EVTX folder and return JSONL result Path
        """
        try:
            _evtx_folder = next(self.orc_dir.rglob("*.evtx"), None)
            if _evtx_folder:
                _evtx_folder.parent
                output_json = self.hayabusa_folder / "hayabusa.jsonl"
                cmd = [
                    self.hayabusa_bin_path,
                    "json-timeline",
                    "-d",
                    str(_evtx_folder.parent),
                    "-p",
                    "all-field-info-verbose",
                    "-ULwqNC",
                    "-o",
                    str(output_json),
                ]
                p = subprocess.Popen(
                    cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=os.environ
                )
                (output, err) = p.communicate()
                p_status = p.wait()

                # self.info(f"[hayabusa] output: {output}")
                self.info(f"[orc_exec_hayabusa] error: {err}")
                self.info(f"[orc_exec_hayabusa] status: {p_status}")
                if not triageutils.file_exists(file=output_json, logger=self.logger):
                    raise Exception("hayabusa no result generated")
                return self.hayabusa_folder / "hayabusa.jsonl"
            else:
                raise Exception("No evtx folder")
        except Exception as ex:
            self.error(f"[orc_exec_hayabusa] {ex}")
            raise ex

    @triageutils.LOG
    def orc_hayabusa_to_elk(self, hayabusa_results:Path, logger:Logger) -> int:
        """
        Fonction qui envoie les résultats hayabusa vers ELK
        Return:
            number of event sent (int)
        """
        try:
            with open(str(hayabusa_results), "r") as jsonl_f:
                json_data = [json.loads(line) for line in jsonl_f]
                for obj in json_data:
                    if type(obj) is dict:
                        try:
                            if "AllFieldInfo" in obj.keys():
                                if isinstance(obj["AllFieldInfo"], dict):
                                    b = dict()
                                    b = {
                                        key: str(value)
                                        for key, value in obj["AllFieldInfo"].items()
                                    }
                                    obj["AllFieldInfo"].update(b)
                                elif isinstance(obj["AllFieldInfo"], str):
                                    b = dict()
                                    b = {"FieldInfo": obj["AllFieldInfo"]}
                                    obj["AllFieldInfo"] = b
                        except Exception as haya_error:
                            self.error(
                                f"[orc_hayabusa_to_elk] Failed to change values type of AllFieldInfo: {haya_error}"
                            )
                if self.is_logstash_active:
                    ip = self.logstash_url
                    if ip.startswith("http"):
                        ip = self.logstash_url.split("//")[1]
                    extrafields = dict()
                    extrafields["csirt"] = dict()
                    extrafields["csirt"]["client"] = self.clientname
                    extrafields["csirt"]["application"] = "alerts"
                    extrafields["csirt"]["hostname"] = self.hostname

                    _event_sent = triageutils.send_data_to_elk(
                        data=json_data,
                        ip=ip,
                        port=self.hayabusa_port,
                        logger=self.logger,
                        extrafields=extrafields,
                    )
                    return _event_sent
                return 0
        except Exception as e:
            self.error(f"[orc_hayabusa_to_elk] {str(e)}")
            raise e


    @triageutils.LOG
    def run(self, logger: Logger):
        """Fonction principale qui exécute tout le triage de orc

        Args:

        Returns:

        """
        try:
            _exceptions = list()
            self.update_workflow_status(
                plugin="orc", module="plugin", status=Status.STARTED
            )
            self.extract_orc_archive(
                archive=self.input_archive,
                dest=self.zip_destination,
                logger=self.logger,
            )
            self.extract_all_7z(logger=self.logger)
            if self.config["run"]["orc"].get("winlogbeat", False):
                self.info("[orc] Run Winlogbeat")
                self.update_workflow_status(
                    plugin="orc", module="winlogbeat", status=Status.STARTED
                )
                try:
                    self.update_workflow_status(
                        plugin="orc",
                        module="winlogbeat",
                        status=Status.STARTED,
                    )
                    if self.is_winlogbeat_active:
                        self.orc_evtx_winlogbeat(logger=self.logger)
                        self.update_workflow_status(
                            plugin="orc",
                            module="winlogbeat",
                            status=Status.FINISHED,
                        )
                    else:
                        raise Exception("Winlogbeat not enabled")
                except Exception as ex:
                    self.error(f"[orc ERROR] {str(ex)}")
                    _exceptions.append(str(ex))
                    self.update_workflow_status(
                        plugin="orc",
                        module="winlogbeat",
                        status=Status.ERROR,
                    )
            if self.config["run"]["orc"].get("evtx", False):
                self.info("[orc] Run EVTX")
                self.update_workflow_status(
                    plugin="orc", module="evtx", status=Status.STARTED
                )
                try:
                    self.orc_parse_evtx(logger=self.logger)
                    self.update_workflow_status(
                        plugin="orc",
                        module="evtx",
                        status=Status.FINISHED,
                    )
                except Exception as ex:
                    self.error(f"[orc ERROR] {str(ex)}")
                    _exceptions.append(str(ex))
                    self.update_workflow_status(
                        plugin="orc", module="evtx", status=Status.ERROR
                    )
            if self.config["run"]["orc"].get("registry", False):
                self.info("[orc] Run Registry")
                self.update_workflow_status(
                    plugin="orc", module="registry", status=Status.STARTED
                )
                try:
                    self.orc_parse_registry(logger=self.logger)
                    self.update_workflow_status(
                        plugin="orc",
                        module="registry",
                        status=Status.FINISHED,
                    )
                except Exception as err_reg:
                    self.error(f"[orc ERROR] {str(err_reg)}")
                    _exceptions.append(str(err_reg))
                    self.update_workflow_status(
                        plugin="orc", module="registry", status=Status.ERROR
                    )
            if self.config["run"]["orc"].get("mft", False):
                self.info("[orc] Run MFT")
                self.update_workflow_status(
                    plugin="orc", module="mft", status=Status.STARTED
                )
                try:
                    self.orc_parse_mft(logger=self.logger)
                    self.update_workflow_status(
                        plugin="orc", module="mft", status=Status.FINISHED
                    )
                except Exception as err_reg:
                    self.error(f"[orc ERROR] {str(err_reg)}")
                    _exceptions.append(str(err_reg))
                    self.update_workflow_status(
                        plugin="orc", module="mft", status=Status.ERROR
                    )
            if self.config["run"]["orc"].get("usnjrnl", False):
                self.info("[orc] Run UsnJrnl")
                self.update_workflow_status(
                    plugin="orc", module="usnjrnl", status=Status.STARTED
                )
                try:
                    self.orc_parse_usn(logger=self.logger)
                    self.update_workflow_status(
                        plugin="orc",
                        module="usnjrnl",
                        status=Status.FINISHED,
                    )
                except Exception as err_reg:
                    self.error(f"[orc ERROR] {str(err_reg)}")
                    _exceptions.append(str(err_reg))
                    self.update_workflow_status(
                        plugin="orc", module="usnjrnl", status=Status.ERROR
                    )
            if self.config["run"]["orc"].get("prefetch", False):
                self.info("[orc] Run Prefetch")
                self.update_workflow_status(
                    plugin="orc", module="prefetch", status=Status.STARTED
                )
                try:
                    self.orc_parse_prefetch(logger=self.logger)
                    self.update_workflow_status(
                        plugin="orc",
                        module="prefetch",
                        status=Status.FINISHED,
                    )
                except Exception as err_reg:
                    self.error(f"[orc ERROR] {str(err_reg)}")
                    _exceptions.append(str(err_reg))
                    self.update_workflow_status(
                        plugin="orc", module="prefetch", status=Status.ERROR
                    )
            if self.config["run"]["orc"].get("mplog", False):
                self.info("[orc] Run MPLog")
                self.update_workflow_status(
                    plugin="orc", module="mplog", status=Status.STARTED
                )
                try:
                    self.orc_parse_mplog(logger=self.logger)
                    self.update_workflow_status(
                        plugin="orc", module="mplog", status=Status.FINISHED
                    )
                except Exception as err_reg:
                    self.error(f"[orc ERROR] {str(err_reg)}")
                    _exceptions.append(str(err_reg))
                    self.update_workflow_status(
                        plugin="orc", module="mplog", status=Status.ERROR
                    )
            if self.config["run"]["orc"].get("activitiescache", False):
                self.info("[orc] Run ActivitiesCache")
                self.update_workflow_status(
                    plugin="orc",
                    module="activitiescache",
                    status=Status.STARTED,
                )
                try:
                    self.orc_parse_activitiescache(logger=self.logger)
                    self.update_workflow_status(
                        plugin="orc",
                        module="activitiescache",
                        status=Status.FINISHED,
                    )
                except Exception as err_reg:
                    self.error(f"[orc ERROR] {str(err_reg)}")
                    _exceptions.append(str(err_reg))
                    self.update_workflow_status(
                        plugin="orc",
                        module="activitiescache",
                        status=Status.ERROR,
                    )
            if self.config["run"]["orc"].get("recyclebin", False):
                self.info("[orc] Run Recycle Bin")
                self.update_workflow_status(
                    plugin="orc", module="recyclebin", status=Status.STARTED
                )
                try:
                    self.orc_parse_recyclebin(logger=self.logger)
                    self.update_workflow_status(
                        plugin="orc",
                        module="recyclebin",
                        status=Status.FINISHED,
                    )
                except Exception as err_reg:
                    self.error(f"[orc ERROR] {str(err_reg)}")
                    _exceptions.append(str(err_reg))
                    self.update_workflow_status(
                        plugin="orc",
                        module="recyclebin",
                        status=Status.ERROR,
                    )
            if self.config["run"]["orc"].get("psreadline", False):
                self.info("[orc] Run PSReadline")
                self.update_workflow_status(
                    plugin="orc", module="psreadline", status=Status.STARTED
                )
                try:
                    self.orc_get_consolehost_history(logger=self.logger)
                    self.update_workflow_status(
                        plugin="orc",
                        module="psreadline",
                        status=Status.FINISHED,
                    )
                except Exception as err_reg:
                    self.error(f"[orc ERROR] {str(err_reg)}")
                    _exceptions.append(str(err_reg))
                    self.update_workflow_status(
                        plugin="orc",
                        module="psreadline",
                        status=Status.ERROR,
                    )
            if self.config["run"]["orc"].get("rdpcache", False):
                self.info("[orc] Run RDPCache")
                self.update_workflow_status(
                    plugin="orc", module="rdpcache", status=Status.STARTED
                )
                try:
                    self.orc_get_RDPCache(logger=self.logger)
                    self.update_workflow_status(
                        plugin="orc",
                        module="rdpcache",
                        status=Status.FINISHED,
                    )
                except Exception as err_rdp:
                    self.error(f"[orc ERROR] {str(err_rdp)}")
                    _exceptions.append(str(err_rdp))
                    self.update_workflow_status(
                        plugin="orc", module="rdpcache", status=Status.ERROR
                    )
            if self.config["run"]["orc"].get("lnk", False):
                self.info("[orc] Run Lnk")
                self.update_workflow_status(
                    plugin="orc", module="lnk", status=Status.STARTED
                )
                try:
                    self.orc_parse_lnk(logger=self.logger)
                    self.update_workflow_status(
                        plugin="orc",
                        module="lnk",
                        status=Status.FINISHED,
                    )
                except Exception as err_lnk:
                    self.error(f"[orc ERROR] {str(err_lnk)}")
                    _exceptions.append(str(err_lnk))
                    self.update_workflow_status(
                        plugin="orc", module="lnk", status=Status.ERROR
                    )
            if self.config["run"]["orc"].get("jumplist", False):
                self.info("[orc] Run JumpList")
                self.update_workflow_status(
                    plugin="orc", module="jumplist", status=Status.STARTED
                )
                try:
                    self.orc_parse_jumplist(logger=self.logger)
                    self.update_workflow_status(
                        plugin="orc",
                        module="jumplist",
                        status=Status.FINISHED,
                    )
                except Exception as err_jumplist:
                    self.error(f"[orc ERROR] {str(err_jumplist)}")
                    _exceptions.append(str(err_jumplist))
                    self.update_workflow_status(
                        plugin="orc", module="jumplist", status=Status.ERROR
                    )
            if self.config["run"]["orc"].get("tasks", False):
                self.info("[orc] Run Tasks")
                self.update_workflow_status(
                    plugin="orc", module="tasks", status=Status.STARTED
                )
                try:
                    self.orc_parse_tasks(logger=self.logger)
                    self.update_workflow_status(
                        plugin="orc",
                        module="tasks",
                        status=Status.FINISHED,
                    )
                except Exception as err_tasks:
                    self.error(f"[orc ERROR] {str(err_tasks)}")
                    _exceptions.append(str(err_tasks))
                    self.update_workflow_status(
                        plugin="orc", module="tasks", status=Status.ERROR
                    )
            if self.config["run"]["orc"].get("webcache", False):
                self.info("[orc] Run WebCache")
                self.update_workflow_status(
                    plugin="orc", module="webcache", status=Status.STARTED
                )
                try:
                    self.orc_parse_webcache(logger=self.logger)
                    self.update_workflow_status(
                        plugin="orc",
                        module="webcache",
                        status=Status.FINISHED,
                    )
                except Exception as err_webcache:
                    self.error(f"[orc ERROR] {str(err_webcache)}")
                    _exceptions.append(str(err_webcache))
                    self.update_workflow_status(
                        plugin="orc", module="webcache", status=Status.ERROR
                    )
            if self.config["run"]["orc"].get("hayabusa", False):
                self.info("[orc] Run HAYABUSA")
                self.update_workflow_status(
                    plugin="orc", module="hayabusa", status=Status.STARTED
                )
                try:
                    _res = self.orc_exec_hayabusa(logger=self.logger)
                    if self.is_logstash_active:
                        self.orc_hayabusa_to_elk(hayabusa_results=_res, logger=self.logger)
                    self.update_workflow_status(
                        plugin="orc", module="hayabusa", status=Status.FINISHED
                    )
                except Exception as err_reg:
                    self.error(f"[orc ERROR] {str(err_reg)}")
                    _exceptions.append(str(err_reg))
                    self.update_workflow_status(
                        plugin="orc", module="hayabusa", status=Status.ERROR
                    )
            if self.config["run"]["orc"].get("plaso", False):
                self.info("[orc] Run PLASO")
                self.update_workflow_status(
                    plugin="orc", module="plaso", status=Status.STARTED
                )
                try:
                    self.generate_plaso_timeline(logger=self.logger)
                    self.update_workflow_status(
                        plugin="orc",
                        module="plaso",
                        status=Status.FINISHED,
                    )
                except Exception as err_reg:
                    self.error(f"[orc ERROR] {str(err_reg)}")
                    _exceptions.append(str(err_reg))
                    self.update_workflow_status(
                        plugin="orc", module="plaso", status=Status.ERROR
                    )
            if len(_exceptions) > 0:
                raise Exception(str(_exceptions))
            self.update_workflow_status(
                plugin="orc", module="plugin", status=Status.FINISHED
            )
        except Exception as ex:
            self.update_workflow_status(
                plugin="orc", module="plugin", status=Status.ERROR
            )
            self.error(f"[orc ERROR] {str(ex)}")
            raise ex
        finally:
            self._docker.kill_containers_by_name(name=self.uuid)
            self.info("[orc] End processing")
