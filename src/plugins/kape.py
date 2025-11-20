import subprocess
import os
import json
import time
import yaml
from re import compile
from typing import Optional
from itertools import islice
from datetime import datetime, timezone
from pathlib import Path
from src.thirdparty import triageutils as triageutils
from src.thirdparty.ParseEVTX import ParseEVTX
from src.thirdparty.ParseRegistry import ParseRegistry
from src.thirdparty.ParseMFT.mft_analyzer import MftAnalyzer
from src.thirdparty.ParseUSNJRNL import ParseUSNJRNL
from src.thirdparty.ParsePrefetch import ParsePrefetch
from src.thirdparty.ParseMPLog import ParseMPLog
from src.thirdparty.winactivities.ParseWinactivities import ParseWinActivities
from src.thirdparty.trashparse.ParseTrash import TrashParse
from src.thirdparty.ParseRDPCache import BMCContainer
from src.thirdparty.ParseLnk import ParseLnk
from src.thirdparty.ParseJumpList import ParseJumpList
from src.thirdparty.ParseTask import ParseTask
from src.thirdparty.ParseWebCache import ParseWebcache
from src.thirdparty.wrapper_docker import WrapperDocker
from logging import Logger
from src import BasePlugin, Status


class Plugin(BasePlugin):
    """
    KAPE plugin pour triage du vhdx
    """

    # @triageutils.LOG
    def __init__(self, conf: dict):
        super().__init__(config=conf)

        self.zipfile = os.path.join(self.upload_dir, conf["archive"]["name"])
        self.vhdx_file = None
        self._docker = WrapperDocker(logger=self.logger)

        self.kape_dir = Path(os.path.join(self.upload_dir, self.hostname, "kape"))
        triageutils.create_directory_path(path=self.kape_dir, logger=self.logger)

        self.zip_destination = Path(os.path.join(self.kape_dir, "extract"))
        triageutils.create_directory_path(path=self.zip_destination, logger=self.logger)
        self.config["general"]["extracted_zip"] = f"{self.zip_destination}"
        self.update_config_file(data=self.config)

        self.mount_point = Path(os.path.join(self.kape_dir, "mnt"))
        triageutils.create_directory_path(path=self.mount_point, logger=self.logger)

        self.plaso_folder = Path(os.path.join(self.kape_dir, "plaso"))
        triageutils.create_directory_path(path=self.plaso_folder, logger=self.logger)

        self.evtx_share = Path(os.path.join(self.kape_dir, "EVTX_Orig"))
        triageutils.create_directory_path(path=self.evtx_share, logger=self.logger)

        self.evtx_parsed_share = Path(os.path.join(self.kape_dir, "EVTX_Parsed"))
        triageutils.create_directory_path(
            path=self.evtx_parsed_share, logger=self.logger
        )

        self.ntfs_share = Path(os.path.join(self.kape_dir, "NTFS"))
        triageutils.create_directory_path(path=self.ntfs_share, logger=self.logger)

        self.reg_share = Path(os.path.join(self.kape_dir, "REGISTRY"))
        triageutils.create_directory_path(path=self.reg_share, logger=self.logger)

        self.iis_share = Path(os.path.join(self.kape_dir, "iis"))
        triageutils.create_directory_path(path=self.iis_share, logger=self.logger)

        self.mplog_share = Path(os.path.join(self.kape_dir, "MPLog"))
        triageutils.create_directory_path(path=self.mplog_share, logger=self.logger)

        self.prefetch_share = Path(os.path.join(self.kape_dir, "Prefetch"))
        triageutils.create_directory_path(path=self.prefetch_share, logger=self.logger)

        self.activitiescache_share = Path(
            os.path.join(self.kape_dir, "ActivitiesCache")
        )
        triageutils.create_directory_path(
            path=self.activitiescache_share, logger=self.logger
        )

        self.recyclebin_dir = Path(os.path.join(self.kape_dir, "RecycleBin"))
        triageutils.create_directory_path(path=self.recyclebin_dir, logger=self.logger)

        self.psreadline_dir = Path(os.path.join(self.kape_dir, "PSReadLine"))
        triageutils.create_directory_path(path=self.psreadline_dir, logger=self.logger)

        self.RDPCache_dir = Path(os.path.join(self.kape_dir, "RDPCache"))
        triageutils.create_directory_path(path=self.RDPCache_dir, logger=self.logger)

        self.lnk_dir = Path(os.path.join(self.kape_dir, "Lnk"))
        triageutils.create_directory_path(path=self.lnk_dir, logger=self.logger)

        self.jumplist_dir = Path(os.path.join(self.kape_dir, "JumpList"))
        triageutils.create_directory_path(path=self.jumplist_dir, logger=self.logger)

        self.tasks_dir = Path(os.path.join(self.kape_dir, "Tasks"))
        triageutils.create_directory_path(path=self.tasks_dir, logger=self.logger)

        self.webcache_dir = Path(os.path.join(self.kape_dir, "WebCache"))
        triageutils.create_directory_path(path=self.webcache_dir, logger=self.logger)

        self.hayabusa_dir = Path(os.path.join(self.kape_dir, "Hayabusa"))
        triageutils.create_directory_path(path=self.hayabusa_dir, logger=self.logger)

    @triageutils.LOG
    def extract_zip(self, archive=None, dest=None, specific_files=[], logger=None):
        """Extrait tous les fichiers de l'archive ZIP contenant les modules et le VHDX.

        Args:
            archive (str): optionnel chemin complet du fichier zip
            dest (str): optionnel chemin complet de décompression de l'archive
            specific_files (tab): optionnel tableau avec le nom de fichier spécifiques à extraire
        """
        try:
            if not archive:
                archive = self.zipfile
            if not dest:
                dest = self.zip_destination
            self.info(f"Zip file: {archive}")
            self.info(f"Dest folder: {dest}")
            try:
                if self.get_vhdx_file():
                    self.info(f"[extract_zip] VHDX already extracted, skipping...")
                    return
            except Exception as ex:
                pass
            triageutils.extract_zip_archive(
                archive=archive,
                dest=dest,
                specific_files=specific_files,
                logger=self.logger,
            )
        except Exception as ex:
            self.logger.error(f"[extract_zip] {ex}")
            raise ex

    @triageutils.LOG
    def get_vhdx_file(self, logger=None) -> Optional[str]:
        """Retourne le nom du fichier vhdx extrait de l'archive.

        Returns:
            Nom du fichier vhdx trouvé sinon None
        """
        if not self.zip_destination:
            raise Exception("ZIP was not extracted")
        _res = triageutils.search_files_by_extension(
            dir=self.zip_destination,
            extension=".vhdx",
            logger=self.logger,
        )
        if len(_res):
            return _res[0]
        else:
            return None

    @triageutils.LOG
    def mountVHDX(self, vhdxfile=None, mountpoint=None, logger=None):
        """Monte le système de fichier du vhdx.
        Args:
            vhdxfile (str): optionnel nom du fichier vhdx
            mountpoint (str): optionnel chemin du point de montage
        Returns:

        """
        m_disk = "/dev/sda1"
        if not vhdxfile:
            raise Exception("[ERROR] No VHDX in archive")
        if not mountpoint:
            mountpoint = self.mount_point
        # for disk in psutil.disk_partitions():
        #    if disk.fstype.lower() == "ntfs":
        #        m_disk = disk.device

        # m_disk = m_disk if m_disk != "" else "/dev/sda1"
        # cmd = ["virt-list-partitions", "-l", vhdxfile]

        vhdx_path = os.path.join(self.zip_destination, vhdxfile)
        cmd = ["virt-filesystems", "-l", "--no-title", "-a", vhdx_path]
        try:
            self.info(f"[virt-filesystems] cmd: {cmd}")
            p = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=os.environ,
            )
            (output, err) = p.communicate()
            p_status = p.wait()
            self.info(f"[virt-filesystems] status: {p_status}")
            if err:
                self.info(f"[virt-filesystems] error: {err}")
            if output:
                self.info(f"[virt-filesystems] output: {output}")
                partitions = output.decode("utf-8").split("\n")
                if len(partitions) > 0:
                    if partitions[0].split(" ")[2].lower() == "ntfs":
                        m_disk = partitions[0].split(" ")[0].lower()
        except Exception as ex:
            self.error(str(ex))
            raise ex

        cmd = ["guestmount", "--add", vhdx_path, "-m", m_disk, "--ro", mountpoint]
        try:
            p = subprocess.Popen(
                cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=os.environ
            )
            (output, err) = p.communicate()
            p_status = p.wait()
            self.info(f"[guestmount] output: {output}")
            self.info(f"[guestmount] error: {err}")
            self.info(f"[guestmount] status: {p_status}")
        except Exception as ex:
            self.error(str(ex))
            raise ex

    @triageutils.LOG
    def unmountVHDX(self, mountpoint=None, logger=None):
        """Démonte le point de montage.
        Args:
            mountpoint (str): optionnel chemin du point de montage
        Returns:

        """
        if not mountpoint:
            mountpoint = self.mount_point
        cmd = ["umount", "-l", mountpoint]
        try:
            p = subprocess.Popen(
                cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=os.environ
            )
            (output, err) = p.communicate()
            p_status = p.wait()
            self.info(f"[guestunmount] output: {output}")
            self.info(f"[guestunmount] error: {err}")
            self.info(f"[guestunmount] status: {p_status}")
        except Exception as ex:
            self.error(str(ex))
            # raise ex

    @triageutils.LOG
    def generate_mft_timeline(self, logger=None):
        """Génère la timeline de $MFT et $UsnJrnl.
        Args:

        Returns:

        """
        try:
            mft = triageutils.search_files(
                src=self.zip_destination, pattern="_MFT.body", logger=self.logger
            )
            mft = mft[0] if len(mft) == 1 else None
            usn = triageutils.search_files(
                src=self.zip_destination, pattern="_UsnJrnl.body", logger=self.logger
            )
            usn = usn[0] if len(usn) == 1 else None
            if mft and usn:
                cmd = [
                    "log2timeline.py",
                    "--status_view",
                    "linear",
                    "--parsers",
                    "mactime",
                    "--storage_file",
                    f"{self.zip_destination}/{self.hostname}-DISK.plaso",
                    f"{self.zip_destination}/modules/FileSystem/",
                ]
            else:
                cmd = [
                    "log2timeline.py",
                    "--status_view",
                    "linear",
                    "--parsers",
                    "mft,usnjrnl",
                    "--storage_file",
                    f"{self.zip_destination}/{self.hostname}-DISK.plaso",
                    self.vhdx_file,
                ]
            self._docker.image = f'{self.docker_images["plaso"]["image"]}:{self.docker_images["plaso"]["tag"]}'
            if not self._docker.is_image_present(name=self._docker.image):
                raise Exception("Image not present")
            self._docker.container = f"{self.uuid}-mft-plaso"
            self._docker.volumes = [f"{self.data_volume}:/data"]
            self._docker.execute_cmd(cmd=cmd)

            s_file = self.plaso_folder / f"{self.hostname}-DISK.plaso"
            triageutils.move_file(
                src=self.zip_destination / f"{self.hostname}-DISK.plaso",
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
        except Exception as ex:
            self.logger.error(f"[generate_mft_timeline] {ex}")
            raise ex

    @triageutils.LOG
    def generate_winarts_timeline(self, logger=None)-> Path:
        """Génère la timeline de pe, prefetch, LNK, JOB, REG, EVTX, firefox_downloads, firefox_history, chrome_27_history.
        Args:

        Returns:

        """
        try:
            cmd = [
                "log2timeline.py",
                "--status_view",
                "linear",
                "--storage-file",
                f"{self.zip_destination}/{self.hostname}-WINARTS.plaso",
                self.vhdx_file,
            ]
            self._docker.image = f'{self.docker_images["plaso"]["image"]}:{self.docker_images["plaso"]["tag"]}'
            if not self._docker.is_image_present(name=self._docker.image):
                raise Exception("Image not present")
            self._docker.container = f"{self.uuid}-winarts-plaso"
            self._docker.volumes = [f"{self.data_volume}:/data"]
            self._docker.execute_cmd(cmd=cmd)
            s_file = self.plaso_folder / f"{self.hostname}-WINARTS.plaso"
            triageutils.move_file(
                src=self.zip_destination / f"{self.hostname}-WINARTS.plaso",
                dst=s_file,
                logger=self.logger,
            )
            if self.is_timesketch_active:
                triageutils.import_timesketch(
                    timelinename=f"{self.hostname}_WINARTS",
                    file=s_file,
                    timesketch_id=self.timesketch_id,
                    logger=self.logger,
                )
            return s_file
        except Exception as ex:
            self.logger.error(f"[generate_winarts_timeline] {ex}")
            raise ex

    @triageutils.LOG
    def generate_psort_timeline(self, plasofile: Path, logger: Logger) -> Path:
        """Génère la timeline avec PSORT du fichier plaso en entrée et l'envoie à ELK.
        Args:
            plasofile (str): chemin du fichier plaso à parser

        Returns:
            (str) file path généré

        """
        file_attribute = ""
        if "WINARTS" in plasofile.as_posix():
            file_attribute = "WINARTS"
        elif "DISK" in plasofile.as_posix():
            file_attribute = "DISK"

        cmd = [
            "psort.py",
            "-o",
            "json_line",
            "-a",
            "-w",
            f"{self.plaso_folder.as_posix()}/psort-{self.hostname}-{file_attribute}.jsonl",
            plasofile.as_posix(),
        ]
        self._docker.image = f'{self.docker_images["plaso"]["image"]}:{self.docker_images["plaso"]["tag"]}'
        if not self._docker.is_image_present(name=self._docker.image):
            raise Exception("Image not present")
        self._docker.container = f"{self.uuid}-psort"
        self._docker.volumes = [f"{self.data_volume}:/data"]
        self._docker.execute_cmd(cmd=cmd)
        s_file = self.plaso_folder / f"psort-{self.hostname}-{file_attribute}.jsonl"
        return s_file

    @triageutils.LOG
    def send_psort_to_elk(self, psortfile="", logger=None) -> None:
        """Fonction qui envoie les résultats psort vers ELK"""
        try:
            if not psortfile:
                raise Exception("No PSORT file given")
            with open(psortfile, "r") as jsonl_f:
                while True:
                    lines = list(islice(jsonl_f, 100))
                    count = 0
                    if lines:
                        count += 100
                        print(f"{count} lines processing...")
                        json_data = [json.loads(line) for line in jsonl_f]
                        ip = self.logstash_url
                        if ip.startswith("http"):
                            ip = self.logstash_url.split("//")[1]
                        extrafields = dict()
                        extrafields["csirt"] = dict()
                        extrafields["csirt"]["client"] = self.clientname
                        extrafields["csirt"]["hostname"] = self.hostname
                        extrafields["csirt"]["application"] = "psort"
                        triageutils.send_data_to_elk(
                            data=json_data,
                            ip=ip,
                            port=self.evtxparser_port,
                            extrafields=extrafields,
                            logger=self.logger,
                        )
                    else:
                        break
        except Exception as e:
            self.error(f"[send_psort_to_elk] {str(e)}")
            raise e

    @triageutils.LOG
    def kape_iis_logs(self, logger: Logger):
        try:
            _found = False
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "inetpub/**/*.log".lower()
            )
            for _f in self.mount_point.rglob(_searchpattern):
                _found = True
                triageutils.copy_file(
                    src=_f, dst=self.iis_share, overwrite=True, logger=self.logger
                )

            if _found and self.is_logstash_active:
                _data = triageutils.generate_iis_filebeat_config(
                    ip=self.logstash_url.split("//")[1],
                    port=self.iis_port,
                    client=self.clientname,
                    hostname=self.hostname,
                    logger=None,
                )
                new_config = self.iis_share / Path("filebeat.docker.yml")
                with open(new_config.as_posix(), "w") as file:
                    yaml.dump(_data, file, sort_keys=False)
                voldisk = [
                    f"{new_config}:/usr/share/filebeat/filebeat.yml:ro",
                ]
                voldisk.append(f"{self.iis_share}:/iis")
                cmd = ["filebeat", "-e", "--once", "--strict.perms=false"]
                self._docker.image = f'{self.docker_images["filebeat"]["image"]}:{self.docker_images["filebeat"]["tag"]}'
                if not self._docker.is_image_present(name=self._docker.image):
                    raise Exception("Image not present")
                self._docker.container = f"{self.uuid}-iis"
                self._docker.volumes = voldisk
                self._docker.execute_cmd(cmd=cmd)
        except Exception as ex:
            self.error(f"[kape_iis_logs] {ex}")
            raise ex

    @triageutils.LOG
    def kape_evtx_winlogbeat(self, logger: Logger):
        try:
            win_log_path = os.path.join(self.winlogbeat, self.clientname, self.hostname)
            triageutils.create_directory_path(path=win_log_path, logger=self.logger)
            for _f in self.mount_point.rglob("*.evtx"):
                triageutils.copy_file(
                    src=_f, dst=self.evtx_share, overwrite=True, logger=self.logger
                )
                triageutils.copy_file(
                    src=_f, dst=win_log_path, overwrite=True, logger=self.logger
                )
        except Exception as ex:
            self.error(f"[kape_evtx_winlogbeat] {ex}")
            raise ex

    @triageutils.LOG
    def kape_parse_evtx(self, logger=None):
        try:
            _ip = self.logstash_url
            if _ip.startswith("http"):
                _ip = self.logstash_url.split("//")[1]
            for _f in self.mount_point.rglob("*.evtx"):
                _p = ParseEVTX(
                    evtxfilepath=_f,
                    ip=_ip,
                    port=self.evtxparser_port,
                    client=self.clientname,
                    hostname=self.hostname,
                    mapping=self.evtx_mapping,
                    output_folder=self.evtx_parsed_share,
                    logstash_is_active=self.is_logstash_active,
                    logger=self.logger,
                )
                self.info(f"[kape_parse_evtx] Parse: {_f}")
                _res = _p.parse_evtx()
                self.info(f"[kape_parse_evtx] {_res}")
        except Exception as ex:
            self.error(f"[kape_parse_evtx] {str(ex)}")
            raise ex

    @triageutils.LOG
    def kape_parse_registry(self, logger=None):
        try:
            _parse_reg = ParseRegistry(logger=self.logger)
            _parse_reg.parse_all(dir_to_reg=self.mount_point, out_folder=self.reg_share)
        except Exception as ex:
            self.error(f"[kape_parse_registry] {str(ex)}")
            raise ex

    @triageutils.LOG
    def kape_parse_mft(self, logger=None):
        try:
            for _f in self.mount_point.rglob("$MFT"):
                # _output_file = f"{self.ntfs_share}/mft_parsed_{int(time.time())}.csv"
                _output_file = f"{self.ntfs_share}/{_f.parts[-2]}_mft.csv"
                _analyzer = MftAnalyzer(
                    mft_file=_f.as_posix(), output_file=_output_file, logger=self.logger
                )
                _analyzer.analyze()
        except Exception as ex:
            self.error(f"[kape_parse_mft] {str(ex)}")
            raise ex

    @triageutils.LOG
    def kape_parse_usnjrnl(self, logger=None):
        try:
            for _f in self.mount_point.rglob("$J"):
                _csv_output_file = self.ntfs_share / f"{_f.parts[-2]}_usn.csv"
                _body_output_file = self.ntfs_share / f"{_f.parts[-2]}_usn.body"
                _analyzer = ParseUSNJRNL(
                    usn_file=_f,
                    result_csv_file=_csv_output_file,
                    result_body_file=_body_output_file,
                    logger=self.logger,
                )
                _analyzer.analyze()
        except Exception as ex:
            self.error(f"[kape_parse_usnjrnl] {str(ex)}")
            raise ex

    @triageutils.LOG
    def kape_parse_prefetch(self, logger=None):
        try:
            for _f in self.mount_point.rglob("*.pf"):
                _output_file = self.prefetch_share / f"{_f.name}.json"
                _analyzer = ParsePrefetch(
                    prefetch=_f,
                    output=_output_file,
                    logger=self.logger,
                )
                _analyzer.analyze()
        except Exception as ex:
            self.error(f"[kape_parse_prefetch] {str(ex)}")
            raise ex

    @triageutils.LOG
    def kape_parse_mplog(self, logger=None):
        try:
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "MPLog-*".lower()
            )
            for _f in self.mount_point.rglob(_searchpattern):
                self.info(f"[kape_parse_mplog] Parse: {_f}")
                _analyzer = ParseMPLog(mplog_file=_f, output_directory=self.mplog_share)
                _analyzer.orchestrator()
        except Exception as ex:
            self.error(f"[kape_parse_mplog] {str(ex)}")
            raise ex

    @triageutils.LOG
    def kape_parse_activitiescache(self, logger: Logger):
        try:
            for _f in self.mount_point.rglob(
                "ConnectedDevicesPlatform/**/ActivitiesCache.db"
            ):
                self.info(f"[kape_parse_activitiescache] Parse: {_f}")
                _analyzer = ParseWinActivities(
                    DBfilepath=_f,
                    output_folder=self.activitiescache_share,
                    logger=self.logger,
                )
                _analyzer.process()
        except Exception as ex:
            self.error(f"[kape_parse_activitiescache] {str(ex)}")
            raise ex

    @triageutils.LOG
    def kape_parse_recyclebin(self, logger: Logger):
        try:
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "$Recycle.Bin".lower()
            )
            for _recyclebin_folder in self.mount_point.rglob(_searchpattern):
                for _dir in triageutils.list_directory_full_path(
                    src=_recyclebin_folder,
                    onlydirs=True,
                    logger=self.logger,
                ):
                    _dir = Path(_dir)
                    self.info(f"[kape_parse_recyclebin] Parse: {_dir}")
                    trash = TrashParse(recyclebin_folder=_dir, logger=self.logger)
                    trash.listfile()
                    trash.parsefile()
                    _output = self.recyclebin_dir / f"{_dir.name}.csv"
                    trash.write_csv(csv_file=_output)
                    _output = self.recyclebin_dir / f"{_dir.name}.jsonl"
                    trash.write_jsonl(jsonl_file=_output)
        except Exception as ex:
            self.error(f"[kape_parse_recyclebin] {ex}")

    @triageutils.LOG
    def kape_get_consolehost_history(self, logger: Logger):
        try:
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "ConsoleHost_history.txt".lower()
            )
            for _f in self.mount_point.rglob(_searchpattern):
                self.info(f"[kape_get_consolehost_history] Parse: {_f}")
                try:
                    _username = _f.parts[_f.parts.index("Users") + 1]
                except Exception as errorname:
                    self.error(f"{errorname}")
                    _username = time.time()
                _dst = self.psreadline_dir / str(_username)
                triageutils.copy_file(
                    src=_f, dst=_dst, overwrite=True, logger=self.logger
                )
        except Exception as ex:
            self.error(f"[kape_get_consolehost_history] {str(ex)}")
            raise ex

    @triageutils.LOG
    def kape_get_RDPCache(self, logger: Logger):
        try:
            for _d in [f for f in self.RDPCache_dir.iterdir() if f.is_dir()]:
                triageutils.delete_directory(src=_d, logger=self.logger)
            # Get BMC files
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "Terminal Server Client/**/*.bmc".lower()
            )
            for _f in self.mount_point.rglob(_searchpattern):
                try:
                    _username = _f.parts[_f.parts.index("Users") + 1]
                except Exception as errorname:
                    self.error(f"{errorname}")
                    _username = time.time()
                _dst = self.RDPCache_dir / str(_username)
                triageutils.copy_file(
                    src=_f, dst=_dst, overwrite=True, logger=self.logger
                )
            # Get BIN files
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "Terminal Server Client/**/*.bin".lower()
            )
            for _f in self.mount_point.rglob(_searchpattern):
                try:
                    _username = _f.parts[_f.parts.index("Users") + 1]
                except Exception as errorname:
                    self.error(f"{errorname}")
                    _username = time.time()
                _dst = self.RDPCache_dir / str(_username)
                triageutils.copy_file(
                    src=_f, dst=_dst, overwrite=True, logger=self.logger
                )
            # Exec parser on subdirectories
            for _d in [f for f in self.RDPCache_dir.iterdir() if f.is_dir()]:
                try:
                    _extract_folder = _d / Path("parsed")
                    triageutils.create_directory_path(
                        path=_extract_folder, logger=self.logger
                    )
                    _bmcc = BMCContainer(logger=self.logger)
                    for _cache_file in [
                        _temp_file
                        for _temp_file in _d.iterdir()
                        if _temp_file.is_file()
                    ]:
                        self.logger.info(
                            f"[kape_get_RDPCache] Processing file: {_cache_file}"
                        )
                        if _bmcc.b_import(_cache_file):
                            _bmcc.b_process()
                            _bmcc.b_export(_extract_folder)
                            _bmcc.b_flush()
                except Exception as ex:
                    self.error(f"[bmcc] {str(ex)}")

        except Exception as ex:
            self.error(f"[kape_get_RDPCache] {str(ex)}")
            raise ex

    @triageutils.LOG
    def kape_parse_lnk(self, logger: Logger):
        try:
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "Recent/**/*.lnk".lower()
            )
            for _f in self.mount_point.rglob(_searchpattern):
                try:
                    _username = _f.parts[_f.parts.index("Users") + 1]
                except Exception as errorname:
                    self.error(f"File not in Users folders: {errorname}")
                    _username = time.time()
                _dst = self.lnk_dir / str(_username)
                triageutils.create_directory_path(path=_dst, logger=self.logger)
                _output_file = _dst / f"{_f.stem}.json"
                _analyzer = ParseLnk(
                    lnk_file=_f,
                    output=_output_file,
                    logger=self.logger,
                )
                _analyzer.analyze()
        except Exception as ex:
            self.error(f"[kape_parse_lnk] {str(ex)}")
            raise ex

    @triageutils.LOG
    def kape_parse_jumplist(self, logger: Logger):
        try:
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl,
                "Recent/**/*.automaticDestinations-ms".lower(),
            )
            for _f in self.mount_point.rglob(_searchpattern):
                try:
                    _username = _f.parts[_f.parts.index("Users") + 1]
                except Exception as errorname:
                    self.error(f"File not in Users folders: {errorname}")
                    _username = time.time()
                _dst = self.jumplist_dir / str(_username)
                triageutils.create_directory_path(path=_dst, logger=self.logger)
                _output_file = _dst / f"{_f.name}.jsonl"
                _analyzer = ParseJumpList(
                    input_file=_f,
                    output_file=_output_file,
                    logger=self.logger,
                )
                _analyzer.analyze_automatic_destinations()
            _searchpatterncustom = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "Recent/**/*.customDestinations-ms".lower()
            )
            for _f in self.mount_point.rglob(_searchpatterncustom):
                try:
                    _username = _f.parts[_f.parts.index("Users") + 1]
                except Exception as errorname:
                    self.error(f"File not in Users folders: {errorname}")
                    _username = time.time()
                _dst = self.jumplist_dir / str(_username)
                triageutils.create_directory_path(path=_dst, logger=self.logger)
                _output_file = _dst / f"{_f.name}.jsonl"
                _analyzer = ParseJumpList(
                    input_file=_f,
                    output_file=_output_file,
                    logger=self.logger,
                )
                _analyzer.analyze_custom_destinations()
        except Exception as ex:
            self.error(f"[kape_parse_lnk] {str(ex)}")
            raise ex

    @triageutils.LOG
    def kape_parse_tasks(self, logger: Logger):
        try:
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "System32/Tasks/*".lower()
            )
            for _f in self.mount_point.rglob(_searchpattern):
                if _f.is_file():
                    try:
                        _output_file = self.tasks_dir / f"{_f.name}.json"
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
            self.error(f"[kape_parse_tasks] {str(ex)}")
            raise ex

    @triageutils.LOG
    def kape_parse_webcache(self, logger: Logger):
        try:
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "WebCacheV01.dat".lower()
            )
            for _f in self.mount_point.rglob(_searchpattern):
                if _f.is_file():
                    try:
                        try:
                            _username = _f.parts[_f.parts.index("Users") + 1]
                        except Exception as errorname:
                            self.error(f"File not in Users folders: {errorname}")
                            _username = time.time()
                        _output_jsonl_file = (
                            self.webcache_dir / f"{_username}_{_f.stem}.jsonl"
                        )
                        if triageutils.file_exists(
                            file=_output_jsonl_file, logger=None
                        ):
                            triageutils.delete_file(src=_output_jsonl_file, logger=None)
                        _analyzer = ParseWebcache(
                            cache_file=_f,
                            result_jsonl_file=_output_jsonl_file,
                            logger=self.logger,
                        )
                        _analyzer.analyze()
                    except Exception as ex:
                        self.error(str(ex))
        except Exception as ex:
            self.error(f"[kape_parse_webcache] {str(ex)}")
            raise ex

    @triageutils.LOG
    def kape_exec_hayabusa(self, logger: Logger) -> Path:
        """
        Execute Hayabusa on EVTX folder and return JSONL result Path
        """
        try:
            _evtx_folder = next(self.mount_point.rglob("*.evtx"), None)
            if _evtx_folder:
                _evtx_folder.parent
                output_json = self.hayabusa_dir / "hayabusa.jsonl"
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
                self.info(f"[kape_exec_hayabusa] error: {err}")
                self.info(f"[kape_exec_hayabusa] status: {p_status}")
                if not triageutils.file_exists(file=output_json, logger=self.logger):
                    raise Exception("hayabusa no result generated")
                return self.hayabusa_dir / "hayabusa.jsonl"
            else:
                raise Exception("No evtx folder")
        except Exception as ex:
            self.error(f"[kape_exec_hayabusa] {ex}")
            raise ex

    @triageutils.LOG
    def kape_hayabusa_to_elk(self, hayabusa_results:Path, logger:Logger) -> int:
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
                                f"[kape_hayabusa_to_elk] Failed to change values type of AllFieldInfo: {haya_error}"
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
            self.error(f"[kape_hayabusa_to_elk] {str(e)}")
            raise e



    @triageutils.LOG
    def run(self, logger: Logger):
        """Fonction principale qui exécute tout le triage de kape

        Args:

        Returns:

        """
        try:
            _exceptions = list()
            self.update_workflow_status(
                plugin="kape", module="plugin", status=Status.STARTED
            )
            self.extract_zip(
                archive=self.zipfile, dest=self.zip_destination, logger=self.logger
            )
            self.vhdx_file = self.get_vhdx_file(logger=self.logger)
            self.mountVHDX(vhdxfile=self.vhdx_file, logger=self.logger)
            try:
                triageutils.copy_directory(
                    src=os.path.join(self.zip_destination, "modules"),
                    dst=self.ntfs_share,
                )
            except Exception as ex:
                self.error(f"[Kape ERROR] {str(ex)}")
                _exceptions.append(str(ex))
            if self.config["run"]["kape"].setdefault("winlogbeat", False):
                self.info("[kape] Run Winlogbeat")
                self.update_workflow_status(
                    plugin="kape", module="winlogbeat", status=Status.STARTED
                )
                try:
                    self.update_workflow_status(
                        plugin="kape",
                        module="winlogbeat",
                        status=Status.STARTED,
                    )
                    if self.is_winlogbeat_active:
                        self.kape_evtx_winlogbeat(logger=self.logger)
                        self.update_workflow_status(
                            plugin="kape",
                            module="winlogbeat",
                            status=Status.FINISHED,
                        )
                    else:
                        raise Exception("Winlogbeat not enabled")
                except Exception as ex:
                    self.error(f"[kape ERROR] {str(ex)}")
                    _exceptions.append(str(ex))
                    self.update_workflow_status(
                        plugin="kape",
                        module="winlogbeat",
                        status=Status.ERROR,
                    )
            if self.config["run"]["kape"].setdefault("evtx", False):
                self.info("[KAPE] Run EVTX")
                self.update_workflow_status(
                    plugin="kape", module="evtx", status=Status.STARTED
                )
                try:
                    self.kape_parse_evtx(logger=self.logger)
                    self.update_workflow_status(
                        plugin="kape", module="evtx", status=Status.FINISHED
                    )
                except Exception as ex:
                    self.error(f"[Kape ERROR] {str(ex)}")
                    _exceptions.append(str(ex))
                    self.update_workflow_status(
                        plugin="kape", module="evtx", status=Status.ERROR
                    )
            if self.config["run"]["kape"].setdefault("registry", False):
                try:
                    self.info("[KAPE] Run Registry")
                    self.update_workflow_status(
                        plugin="kape", module="registry", status=Status.STARTED
                    )
                    self.kape_parse_registry(logger=self.logger)
                    self.update_workflow_status(
                        plugin="kape", module="registry", status=Status.FINISHED
                    )
                except Exception as ex:
                    self.error(f"[Kape ERROR] {str(ex)}")
                    _exceptions.append(str(ex))
                    self.update_workflow_status(
                        plugin="kape", module="registry", status=Status.ERROR
                    )
            if self.config["run"]["kape"].setdefault("mft", False):
                try:
                    self.info("[KAPE] Run MFT")
                    self.update_workflow_status(
                        plugin="kape", module="mft", status=Status.STARTED
                    )
                    self.kape_parse_mft(logger=self.logger)
                    self.update_workflow_status(
                        plugin="kape", module="mft", status=Status.FINISHED
                    )
                except Exception as ex:
                    self.error(f"[Kape ERROR] {str(ex)}")
                    _exceptions.append(str(ex))
                    self.update_workflow_status(
                        plugin="kape", module="mft", status=Status.ERROR
                    )
            if self.config["run"]["kape"].setdefault("usnjrnl", False):
                try:
                    self.info("[KAPE] Run UsnJrnl")
                    self.update_workflow_status(
                        plugin="kape", module="usnjrnl", status=Status.STARTED
                    )
                    self.kape_parse_usnjrnl(logger=self.logger)
                    self.update_workflow_status(
                        plugin="kape", module="usnjrnl", status=Status.FINISHED
                    )
                except Exception as ex:
                    self.error(f"[Kape ERROR] {str(ex)}")
                    _exceptions.append(str(ex))
                    self.update_workflow_status(
                        plugin="kape", module="usnjrnl", status=Status.ERROR
                    )
            if self.config["run"]["kape"].setdefault("prefetch", False):
                try:
                    self.info("[kape] Run Prefetch")
                    self.update_workflow_status(
                        plugin="kape", module="prefetch", status=Status.STARTED
                    )
                    self.kape_parse_prefetch(logger=self.logger)
                    self.update_workflow_status(
                        plugin="kape", module="prefetch", status=Status.FINISHED
                    )
                except Exception as ex:
                    self.error(f"[Kape ERROR] {str(ex)}")
                    _exceptions.append(str(ex))
                    self.update_workflow_status(
                        plugin="kape", module="prefetch", status=Status.ERROR
                    )
            if self.config["run"]["kape"].setdefault("mplog", False):
                try:
                    self.info("[kape] Run MPLog")
                    self.update_workflow_status(
                        plugin="kape", module="mplog", status=Status.STARTED
                    )
                    self.kape_parse_mplog(logger=self.logger)
                    self.update_workflow_status(
                        plugin="kape", module="mplog", status=Status.FINISHED
                    )
                except Exception as ex:
                    self.error(f"[Kape ERROR] {str(ex)}")
                    _exceptions.append(str(ex))
                    self.update_workflow_status(
                        plugin="kape", module="mplog", status=Status.ERROR
                    )
            if self.config["run"]["kape"].setdefault("activitiescache", False):
                try:
                    self.info("[kape] Run ActivitiesCache")
                    self.update_workflow_status(
                        plugin="kape", module="activitiescache", status=Status.STARTED
                    )
                    self.kape_parse_activitiescache(logger=self.logger)
                    self.update_workflow_status(
                        plugin="kape", module="activitiescache", status=Status.FINISHED
                    )
                except Exception as ex:
                    self.error(f"[Kape ERROR] {str(ex)}")
                    _exceptions.append(str(ex))
                    self.update_workflow_status(
                        plugin="kape", module="activitiescache", status=Status.ERROR
                    )
            if self.config["run"]["kape"].setdefault("recyclebin", False):
                try:
                    self.info("[kape] Run Recycle Bin")
                    self.update_workflow_status(
                        plugin="kape", module="recyclebin", status=Status.STARTED
                    )
                    self.kape_parse_recyclebin(logger=self.logger)
                    self.update_workflow_status(
                        plugin="kape", module="recyclebin", status=Status.FINISHED
                    )
                except Exception as err_reg:
                    self.error(f"[kape ERROR] {str(err_reg)}")
                    _exceptions.append(str(err_reg))
                    self.update_workflow_status(
                        plugin="kape", module="recyclebin", status=Status.ERROR
                    )
            if self.config["run"]["kape"].setdefault("psreadline", False):
                try:
                    self.info("[kape] Run PSReadline")
                    self.update_workflow_status(
                        plugin="kape", module="psreadline", status=Status.STARTED
                    )
                    self.kape_get_consolehost_history(logger=self.logger)
                    self.update_workflow_status(
                        plugin="kape", module="psreadline", status=Status.FINISHED
                    )
                except Exception as err_reg:
                    self.error(f"[kape ERROR] {str(err_reg)}")
                    _exceptions.append(str(err_reg))
                    self.update_workflow_status(
                        plugin="kape", module="psreadline", status=Status.ERROR
                    )
            if self.config["run"]["kape"].setdefault("rdpcache", False):
                try:
                    self.info("[kape] Run RDPCache")
                    self.update_workflow_status(
                        plugin="kape", module="rdpcache", status=Status.STARTED
                    )
                    self.kape_get_RDPCache(logger=self.logger)
                    self.update_workflow_status(
                        plugin="kape", module="rdpcache", status=Status.FINISHED
                    )
                except Exception as err_rdp:
                    self.error(f"[kape ERROR] {str(err_rdp)}")
                    _exceptions.append(str(err_rdp))
                    self.update_workflow_status(
                        plugin="kape", module="rdpcache", status=Status.ERROR
                    )
            if self.config["run"]["kape"].setdefault("lnk", False):
                try:
                    self.info("[kape] Run LNK")
                    self.update_workflow_status(
                        plugin="kape", module="lnk", status=Status.STARTED
                    )
                    self.kape_parse_lnk(logger=self.logger)
                    self.update_workflow_status(
                        plugin="kape", module="lnk", status=Status.FINISHED
                    )
                except Exception as err_rdp:
                    self.error(f"[kape ERROR] {str(err_rdp)}")
                    _exceptions.append(str(err_rdp))
                    self.update_workflow_status(
                        plugin="kape", module="lnk", status=Status.ERROR
                    )
            if self.config["run"]["kape"].setdefault("jumplist", False):
                try:
                    self.info("[kape] Run JumpList")
                    self.update_workflow_status(
                        plugin="kape", module="jumplist", status=Status.STARTED
                    )
                    self.kape_parse_jumplist(logger=self.logger)
                    self.update_workflow_status(
                        plugin="kape", module="jumplist", status=Status.FINISHED
                    )
                except Exception as err_rdp:
                    self.error(f"[kape ERROR] {str(err_rdp)}")
                    _exceptions.append(str(err_rdp))
                    self.update_workflow_status(
                        plugin="kape", module="jumplist", status=Status.ERROR
                    )
            if self.config["run"]["kape"].setdefault("tasks", False):
                self.info("[kape] Run Tasks")
                self.update_workflow_status(
                    plugin="kape", module="tasks", status=Status.STARTED
                )
                try:
                    self.kape_parse_tasks(logger=self.logger)
                    self.update_workflow_status(
                        plugin="kape",
                        module="tasks",
                        status=Status.FINISHED,
                    )
                except Exception as err_tasks:
                    self.error(f"[kape ERROR] {str(err_tasks)}")
                    _exceptions.append(str(err_tasks))
                    self.update_workflow_status(
                        plugin="kape", module="tasks", status=Status.ERROR
                    )
            if self.config["run"]["kape"].setdefault("webcache", False):
                self.info("[kape] Run WebCache")
                self.update_workflow_status(
                    plugin="kape", module="webcache", status=Status.STARTED
                )
                try:
                    self.kape_parse_webcache(logger=self.logger)
                    self.update_workflow_status(
                        plugin="kape",
                        module="webcache",
                        status=Status.FINISHED,
                    )
                except Exception as err_webcache:
                    self.error(f"[kape ERROR] {str(err_webcache)}")
                    _exceptions.append(str(err_webcache))
                    self.update_workflow_status(
                        plugin="kape", module="webcache", status=Status.ERROR
                    )
            if self.config["run"]["kape"].setdefault("hayabusa", False):
                self.info("[kape] Run HAYABUSA")
                self.update_workflow_status(
                    plugin="kape", module="hayabusa", status=Status.STARTED
                )
                try:
                    _res = self.kape_exec_hayabusa(logger=self.logger)
                    if self.is_logstash_active:
                        self.kape_hayabusa_to_elk(hayabusa_results=_res, logger=self.logger)
                    self.update_workflow_status(
                        plugin="kape", module="hayabusa", status=Status.FINISHED
                    )
                except Exception as err_reg:
                    self.error(f"[kape ERROR] {str(err_reg)}")
                    _exceptions.append(str(err_reg))
                    self.update_workflow_status(
                        plugin="kape", module="hayabusa", status=Status.ERROR
                    )
            if self.config["run"]["kape"].setdefault("iis", False):
                try:
                    self.info("[KAPE] Run IIS")
                    self.update_workflow_status(
                        plugin="kape", module="iis", status=Status.STARTED
                    )
                    self.kape_iis_logs(logger=self.logger)
                    self.update_workflow_status(
                        plugin="kape", module="iis", status=Status.FINISHED
                    )
                except Exception as ex:
                    self.error(f"[Kape ERROR] {str(ex)}")
                    _exceptions.append(str(ex))
                    self.update_workflow_status(
                        plugin="kape", module="iis", status=Status.ERROR
                    )
            if self.config["run"]["kape"].setdefault("plaso", False):
                try:
                    self.info("[KAPE] Run PLASO")
                    self.update_workflow_status(
                        plugin="kape", module="plaso", status=Status.STARTED
                    )
                    self.generate_mft_timeline(logger=self.logger)
                    _plaso_file = self.generate_winarts_timeline(logger=self.logger)
                    if not self.is_timesketch_active:
                        self.generate_psort_timeline(plasofile=_plaso_file,logger=self.logger)
                    self.update_workflow_status(
                        plugin="kape", module="plaso", status=Status.FINISHED
                    )
                except Exception as ex:
                    self.error(f"[Kape ERROR] {str(ex)}")
                    _exceptions.append(str(ex))
                    self.update_workflow_status(
                        plugin="kape", module="plaso", status=Status.ERROR
                    )
            if len(_exceptions) > 0:
                raise Exception(str(_exceptions))
            self.update_workflow_status(
                plugin="kape", module="plugin", status=Status.FINISHED
            )
        except Exception as ex:
            self.update_workflow_status(
                plugin="kape", module="plugin", status=Status.ERROR
            )
            self.error(f"[KAPE ERROR] {str(ex)}")
            raise ex
        finally:
            if self.vhdx_file:
                self.unmountVHDX(logger=self.logger)
            self._docker.kill_containers_by_name(name=self.uuid)
            triageutils.delete_directory(src=self.mount_point, logger=self.logger)
            self.info("[KAPE] End processing")
