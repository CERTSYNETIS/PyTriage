import subprocess
import os
import json
import time
from typing import Optional
from itertools import islice
from datetime import datetime, timezone
from dateutil.relativedelta import relativedelta

from pathlib import Path

import docker
from src.thirdparty import triageutils as triageutils
from src.thirdparty.ParseEVTX import ParseEVTX
from src.thirdparty.ParseRegistry import ParseRegistry
from src.thirdparty.ParseMFT.mft_analyzer import MftAnalyzer
from src.thirdparty.ParseUSNJRNL import ParseUSNJRNL
from src.thirdparty.ParsePrefetch import ParsePrefetch
from src.thirdparty.ParseMPLog import ParseMPLog
from src.thirdparty.winactivities.ParseWinactivities import ParseWinActivities
from src.thirdparty.trashparse.ParseTrash import TrashParse
from logging import Logger
from src import BasePlugin


class Plugin(BasePlugin):
    """
    KAPE plugin pour triage du vhdx
    """

    # @triageutils.LOG
    def __init__(self, conf: dict):
        super().__init__(config=conf)

        self.zipfile = os.path.join(self.upload_dir, conf["archive"]["name"])
        self.vhdx_file = None

        self.kape_dir = os.path.join(self.upload_dir, self.hostname, "kape")
        triageutils.create_directory_path(path=self.kape_dir, logger=self.logger)

        self.zip_destination = os.path.join(self.kape_dir, "extract")
        triageutils.create_directory_path(path=self.zip_destination, logger=self.logger)

        self.mount_point = os.path.join(self.kape_dir, "mnt")
        triageutils.create_directory_path(path=self.mount_point, logger=self.logger)
        self.config["general"]["extracted_zip"] = f"{self.mount_point}"
        _updt = triageutils.update_config_file(
            data=self.config,
            conf_file=f'{self.config["general"]["extract"]}/config.yaml',
            logger=self.logger,
        )

        self.plaso_folder = os.path.join(self.kape_dir, "plaso")
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

        self.iis_share = os.path.join(self.kape_dir, "iis")
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
    def get_evtx(self, evtx_folder=None, logger=None) -> list:
        """Copie les fichiers evtx présents dans le dossier vers le dossier partagé.
        Args:
            evtx_folder (str): optionnel chemin du dossier contenant les fichiers evtx si pas de dossier, il cherche dans tout le vhdx
        Returns:
            un tableau contenant le nom de tous les fichiers trouvés
        """
        records = []
        if not evtx_folder:
            evtx_folder = self.mount_point
        records.extend(
            triageutils.search_files(
                src=evtx_folder, pattern=".evtx", logger=self.logger
            )
        )
        if len(records):
            triageutils.copy_files(
                src=records, dst=self.evtx_share, overwrite=True, logger=self.logger
            )
        return records

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
    def check_docker_image(
        self,
        image_name="dockerhub.cert.lan/log2timeline/plaso",
        tag="20230717",
        logger=None,
    ):
        try:
            _docker = docker.from_env()
            self.info(f"Is image present: {image_name}, tag:{tag}")
            all_images = []
            for image in _docker.images.list():
                for key, value in image.attrs.items():
                    if key == "RepoTags":
                        all_images.extend(value)
            if f"{image_name}:{tag}" in all_images:
                self.info("Image is present")
            else:
                self.info("Pulling image...")
                _docker.images.pull(repository=image_name, tag=tag)
        except Exception as ex:
            self.error(f"[check_docker_image] {ex}")
            raise ex

    @triageutils.LOG
    def kill_docker_container(self, logger=None):
        _docker = docker.from_env()
        self.info("== Containers ==")
        for container in _docker.containers.list():
            self.info(f"{container.name}")
            if f"{self.clientname}-{self.hostname}-" in container.name:
                self.info(f"Delete container: {container.name}")
                container.kill()
                container.remove(force=True)
        _docker.close()

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
            _docker = docker.from_env()
            self.info(f"Docker volume to mount: {self.data_volume}")
            if mft and usn:
                self.info("Start Docker log2timeline/plaso on $MFT,$UsnJrnl files")
                # cmd = f"log2timeline.py --worker_memory_limit 4000000000 --parsers mactime --storage_file /data/{self.hostname}-DISK.plaso /data/modules/FileSystem/"
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
                container = _docker.containers.run(
                    image=f'{self.docker_images["plaso"]["image"]}:{self.docker_images["plaso"]["tag"]}',
                    auto_remove=True,
                    detach=True,
                    command=cmd,
                    volumes=[f"{self.data_volume}:/data"],
                    stderr=True,
                    stdout=True,
                    name=f"{self.clientname}-{self.hostname}-DISK",
                )
                container.wait()
                self.info("STOP Docker log2timeline/plaso on $MFT,$UsnJrnl files")
            else:
                self.info("Start Docker log2timeline/plaso on VHDX file")
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
                container = _docker.containers.run(
                    image=f'{self.docker_images["plaso"]["image"]}:{self.docker_images["plaso"]["tag"]}',
                    auto_remove=True,
                    detach=True,
                    command=cmd,
                    volumes=[f"{self.data_volume}:/data"],
                    stderr=True,
                    stdout=True,
                    name=f"{self.clientname}-{self.hostname}-DISK",
                )
                container.wait()
                self.info("STOP Docker log2timeline/plaso on VHDX file")

            s_file = os.path.join(self.plaso_folder, f"{self.hostname}-DISK.plaso")
            triageutils.move_file(
                src=os.path.join(self.zip_destination, f"{self.hostname}-DISK.plaso"),
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

    @triageutils.LOG
    def generate_winarts_timeline(self, logger=None):
        """Génère la timeline de pe, prefetch, LNK, JOB, REG, EVTX, firefox_downloads, firefox_history, chrome_27_history.
        Args:

        Returns:

        """
        # client = docker.from_env()
        try:
            self.info("Start Docker log2timeline/plaso on winarts")
            cmd = [
                "log2timeline.py",
                "--status_view",
                "linear",
                "--storage-file",
                f"{self.zip_destination}/{self.hostname}-WINARTS.plaso",
                self.vhdx_file,
            ]
            _docker = docker.from_env()
            container = _docker.containers.run(
                image=f'{self.docker_images["plaso"]["image"]}:{self.docker_images["plaso"]["tag"]}',
                auto_remove=True,
                detach=True,
                command=cmd,
                volumes=[f"{self.data_volume}:/data"],
                stderr=True,
                stdout=True,
                name=f"{self.clientname}-{self.hostname}-WINARTS",
            )
            container.wait()
            self.info("STOP Docker log2timeline/plaso on winarts")
            s_file = os.path.join(self.plaso_folder, f"{self.hostname}-WINARTS.plaso")
            triageutils.move_file(
                src=os.path.join(
                    self.zip_destination, f"{self.hostname}-WINARTS.plaso"
                ),
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
        except Exception as ex:
            self.logger.error(f"[generate_winarts_timeline] {ex}")

    @triageutils.LOG
    def generate_psort_timeline(self, plasofile="", logger=None) -> str:
        """Génère la timeline avec PSORT du fichier plaso en entrée et l'envoie à ELK.
        Args:
            plasofile (str): chemin du fichier plaso à parser

        Returns:
            (str) file path généré

        """
        # client = docker.from_env()
        if not plasofile:
            raise Exception("No PLASO file given")
        self.info(f"Start Docker PLASO/psort on {plasofile}")
        file_attribute = ""
        if "WINARTS" in plasofile:
            file_attribute = "WINARTS"
        elif "DISK" in plasofile:
            file_attribute = "DISK"

        """
        now_date = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        start_date = (datetime.now(timezone.utc) - relativedelta(years=1)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        cmd.append(f"date < '{now_date}' and date > '{start_date}'")
        """

        slice = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        slice_size = 1051200

        cmd = [
            "psort.py",
            "-o",
            "json_line",
            "--slice",
            slice,
            "--slice_size",
            slice_size,
            "-a",
            "-w",
            f"{self.plaso_folder}/psort-{self.hostname}-{file_attribute}.jsonl",
            f"{self.plaso_folder}/{plasofile}",
        ]

        _docker = docker.from_env()
        container = _docker.containers.run(
            image=f'{self.docker_images["plaso"]["image"]}:{self.docker_images["plaso"]["tag"]}',
            auto_remove=True,
            detach=True,
            command=cmd,
            volumes=[f"{self.data_volume}:/data"],
            stderr=True,
            stdout=True,
            name=f"{self.clientname}-{self.hostname}-PSORT",
        )
        container.wait()
        self.info(f"STOP Docker PLASO/psort on {plasofile}")
        s_file = os.path.join(
            self.plaso_folder, f"psort-{self.hostname}-{file_attribute}.jsonl"
        )
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
    def get_iis_logs(self, iis_folder=None, logger=None) -> list:
        """Copie les fichiers de logs du serveur IIS présents dans le dossier vers le dossier partagé.
        Args:
            iis_folder (str): optionnel chemin du dossier
        Returns:
            un tableau contenant le nom de tous les fichiers trouvés
        """
        records = []
        pattern = ".log"
        if not iis_folder:
            for letter in [
                "a",
                "b",
                "c",
                "d",
                "e",
                "f",
                "g",
                "h",
                "i",
                "j",
                "k",
                "l",
                "m",
                "n",
                "o",
                "p",
                "q",
                "r",
                "s",
                "t",
                "u",
                "v",
                "w",
                "x",
                "y",
                "z",
                "A",
                "B",
                "C",
                "D",
                "E",
                "F",
                "G",
                "H",
                "I",
                "J",
                "K",
                "L",
                "M",
                "N",
                "O",
                "P",
                "Q",
                "R",
                "S",
                "T",
                "U",
                "V",
                "W",
                "X",
                "Y",
                "Z",
            ]:
                if triageutils.directory_exists(
                    dir=os.path.join(self.mount_point, letter), logger=self.logger
                ):
                    iis_folder = os.path.join(
                        self.mount_point, letter, "inetpub", "logs", "LogFiles"
                    )
                    if triageutils.directory_exists(dir=iis_folder, logger=self.logger):
                        triageutils.copy_directory(
                            src=iis_folder, dst=self.iis_share, logger=self.logger
                        )
                    break
        else:
            if triageutils.directory_exists(dir=iis_folder, logger=self.logger):
                triageutils.copy_directory(
                    src=iis_folder, dst=self.iis_share, logger=self.logger
                )
        records.extend(
            triageutils.search_files(
                src=self.iis_share, pattern=pattern, logger=self.logger
            )
        )
        return records

    @triageutils.LOG
    def send_iis_logs(self, iis_logs=[], logger=None) -> bool:
        """Parse les fichiers de log IIS puis les envoies vers ELK.
        Args:
            iis_logs (list): Liste contenant les chemins des fichiers de log
        Returns:

        """
        if not len(iis_logs):
            # iis_logs = triageutils.search_files(dir=self.iis_folder, pattern=".log")
            self.error("[send_iis_logs] No IIS logs to send")
            return False
        count = 0
        total = len(iis_logs)
        ip = self.logstash_url
        if ip.startswith("http"):
            ip = self.logstash_url.split("//")[1]
        for file in iis_logs:
            try:  # For non blocking error
                if file.endswith(".log"):  # PROCESS only Log files
                    json_tab = []
                    with open(file, "r", errors="ignore") as log_to_parse:
                        count += 1
                        Lines = log_to_parse.readlines()
                        header_ok = False
                        header = []
                        for line in Lines:
                            if line.startswith("#Fields:") and not header_ok:
                                header_ok = True
                                header = line.split("#Fields: ")[1].split()
                            elif not line.startswith("#"):
                                fields = line.split()
                                data_to_send = dict(zip(header, fields))
                                # data_to_send["host_log_path"] = file
                                data_to_send["log"] = dict()
                                data_to_send["log"]["file"] = dict()
                                data_to_send["log"]["file"]["path"] = file
                                data_to_send["full_message"] = line
                                data_to_send["csirt"] = dict()
                                data_to_send["csirt"]["client"] = self.clientname
                                data_to_send["csirt"]["hostname"] = self.hostname
                                data_to_send["csirt"]["application"] = "iis"
                                json_tab.append(data_to_send)
                    self.info(f"[send_iis_logs] send file {count}/{total}")
                    triageutils.send_data_to_elk(
                        data=json_tab,
                        ip=ip,
                        port=self.iis_port,
                        logger=self.logger,
                    )
            except Exception as ex:
                self.error(f"[send_iis_logs] {ex} ")
        return True

    @triageutils.LOG
    def send_logs_to_winlogbeat(self, evtx_logs=[], logger=None) -> bool:
        """Copie les evtx vers le dossier partagé sur la VM Winlogbeat.
        Args:
            evtx_logs (list): Liste contenant les chemins des fichiers de log
        Returns:
            result (bool): True or False
        """
        result = True
        self.info(f"[send_logs_to_winlogbeat] Total EVTX: {len(evtx_logs)}")
        if not len(evtx_logs):
            self.error("[send_logs_to_winlogbeat] No EVTX logs to send")
            return False
        try:
            win_log_path = os.path.join(self.winlogbeat, self.clientname, self.hostname)
            if triageutils.create_directory_path(path=win_log_path, logger=self.logger):
                self.info(
                    f"[send_logs_to_winlogbeat] WinLogBeat created: {win_log_path}"
                )
                result &= triageutils.copy_files(
                    src=evtx_logs, dst=win_log_path, overwrite=True, logger=self.logger
                )
        except Exception as ex:
            self.error(f"[send_logs_to_winlogbeat] {ex}")
        self.info(f"[send_logs_to_winlogbeat] result: {result}")
        return result

    @triageutils.LOG
    def kape_parse_evtx(self, logger=None):
        try:
            _ip = self.logstash_url
            if _ip.startswith("http"):
                _ip = self.logstash_url.split("//")[1]
            for _f in triageutils.search_files_by_extension_generator(
                src=self.mount_point, extension=".evtx", logger=self.logger
            ):
                triageutils.copy_file(
                    src=_f,
                    dst=self.evtx_share,
                    overwrite=True,
                    logger=self.logger,
                )
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
            _mft_files = triageutils.search_files(
                src=self.mount_point, pattern="$MFT", strict=True
            )
            if len(_mft_files):
                _output_file = f"{self.ntfs_share}/mft_parsed.csv"
                _mft = _mft_files[0]
                _analyzer = MftAnalyzer(
                    mft_file=_mft, output_file=_output_file, logger=self.logger
                )
                _analyzer.analyze()
            else:
                self.logger.error(f"[kape_parse_mft] No $MFT found")
        except Exception as ex:
            self.error(f"[kape_parse_mft] {str(ex)}")
            raise ex

    @triageutils.LOG
    def kape_parse_usnjrnl(self, logger=None):
        try:
            _usn_files = triageutils.search_files(
                src=self.mount_point, pattern="$J", strict=True
            )
            if len(_usn_files):
                _csv_output_file = Path(f"{self.ntfs_share}/usn_parsed.csv")
                _usn = Path(_usn_files[0])
                _analyzer = ParseUSNJRNL(
                    usn_file=_usn, result_csv_file=_csv_output_file, logger=self.logger
                )
                _analyzer.analyze()
            else:
                self.logger.error(f"[kape_parse_usnjrnl] No $J found")
        except Exception as ex:
            self.error(f"[kape_parse_usnjrnl] {str(ex)}")
            raise ex

    @triageutils.LOG
    def kape_parse_prefetch(self, logger=None):
        try:
            for _f in triageutils.search_files_by_extension_generator(
                src=self.mount_point,
                extension=".pf",
                patterninpath="prefetch",
                logger=self.logger,
            ):
                _output_file = Path(f"{self.prefetch_share}/{_f.parts[-1]}.json")
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
            for _f in triageutils.search_files_generator(
                src=self.mount_point, pattern="MPLog-", patterninpath="Windows Defender"
            ):
                self.info(f"[kape_parse_mplog] Parse: {_f}")
                _analyzer = ParseMPLog(mplog_file=_f, output_directory=self.mplog_share)
                _analyzer.orchestrator()
        except Exception as ex:
            self.error(f"[kape_parse_mplog] {str(ex)}")
            raise ex

    @triageutils.LOG
    def kape_parse_activitiescache(self, logger: Logger):
        try:
            for _f in triageutils.search_files_generator(
                src=self.mount_point,
                pattern="ActivitiesCache.db",
                patterninpath="ConnectedDevicesPlatform",
                strict=True,
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
            _recyclebin_folder = triageutils.get_folder_path_by_name(
                folder_name="$Recycle.Bin", root=self.mount_point, logger=self.logger
            )
            if _recyclebin_folder:
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
                    _output = Path(self.recyclebin_dir / Path(f"{_dir.name}.csv"))
                    trash.write_csv(csv_file=_output)
                    _output = Path(self.recyclebin_dir / Path(f"{_dir.name}.jsonl"))
                    trash.write_jsonl(jsonl_file=_output)
            else:
                self.info("[kape_parse_recyclebin] No {$Recycle.Bin} Folder")
        except Exception as ex:
            self.error(f"[kape_parse_recyclebin] {ex}")

    @triageutils.LOG
    def kape_get_consolehost_history(self, logger: Logger):
        try:
            for _f in triageutils.search_files_generator(
                src=self.zip_destination,
                pattern="ConsoleHost_history.txt",
                patterninpath="PSReadLine",
                strict=True,
            ):
                self.info(f"[kape_get_consolehost_history] Parse: {_f}")
                try:
                    _username = _f.parts[_f.parts.index("Users") + 1]
                except Exception as errorname:
                    self.error(f"{errorname}")
                    _username = time.time()
                _dst = self.psreadline_dir / Path(f"{_username}")
                triageutils.copy_file(
                    src=_f, dst=_dst, overwrite=True, logger=self.logger
                )
        except Exception as ex:
            self.error(f"[kape_get_consolehost_history] {str(ex)}")
            raise ex

    @triageutils.LOG
    def run(self, logger: Logger):
        """Fonction principale qui exécute tout le triage de kape

        Args:

        Returns:

        """
        try:
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
            if self.config["run"]["kape"].get("evtx", False):
                self.info("[KAPE] Run EVTX")
                try:
                    if self.config["run"]["kape"]["winlogbeat"]:
                        evtx_logs = self.get_evtx(logger=self.logger)
                        if self.is_winlogbeat_active:
                            self.send_logs_to_winlogbeat(
                                evtx_logs=evtx_logs, logger=self.logger
                            )
                    else:
                        self.kape_parse_evtx(logger=self.logger)
                        self.info("[kape] EVTX process done")
                except Exception as ex:
                    self.error(f"[Kape ERROR] {str(ex)}")
            if self.config["run"]["kape"].get("registry", False):
                try:
                    self.info("[KAPE] Run Registry")
                    self.kape_parse_registry(logger=self.logger)
                except Exception as ex:
                    self.error(f"[Kape ERROR] {str(ex)}")
            if self.config["run"]["kape"].get("mft", False):
                try:
                    self.info("[KAPE] Run MFT")
                    self.kape_parse_mft(logger=self.logger)
                except Exception as ex:
                    self.error(f"[Kape ERROR] {str(ex)}")
            if self.config["run"]["kape"].get("usnjrnl", False):
                try:
                    self.info("[KAPE] Run UsnJrnl")
                    self.kape_parse_usnjrnl(logger=self.logger)
                except Exception as ex:
                    self.error(f"[Kape ERROR] {str(ex)}")
            if self.config["run"]["kape"].get("prefetch", False):
                try:
                    self.info("[kape] Run Prefetch")
                    self.kape_parse_prefetch(logger=self.logger)
                except Exception as ex:
                    self.error(f"[Kape ERROR] {str(ex)}")
            if self.config["run"]["kape"].get("mplog", False):
                try:
                    self.info("[kape] Run MPLog")
                    self.kape_parse_mplog(logger=self.logger)
                except Exception as ex:
                    self.error(f"[Kape ERROR] {str(ex)}")
            if self.config["run"]["kape"].get("activitiescache", False):
                try:
                    self.info("[kape] Run ActivitiesCache")
                    self.kape_parse_activitiescache(logger=self.logger)
                except Exception as ex:
                    self.error(f"[Kape ERROR] {str(ex)}")
            if self.config["run"]["kape"].get("recyclebin", False):
                self.info("[kape] Run Recycle Bin")
                try:
                    self.kape_parse_recyclebin(logger=self.logger)
                except Exception as err_reg:
                    self.error(f"[kape ERROR] {str(err_reg)}")
            if self.config["run"]["kape"].get("psreadline", False):
                self.info("[kape] Run PSReadline")
                try:
                    self.kape_get_consolehost_history(logger=self.logger)
                except Exception as err_reg:
                    self.error(f"[kape ERROR] {str(err_reg)}")
            if self.config["run"]["kape"].get("iis", False):
                try:
                    self.info("[KAPE] Run IIS")
                    res = self.get_iis_logs(logger=self.logger)
                    if self.is_logstash_active:
                        self.send_iis_logs(iis_logs=res, logger=self.logger)
                except Exception as ex:
                    self.error(f"[Kape ERROR] {str(ex)}")
            if self.config["run"]["kape"].get("timeline", False):
                self.info("[KAPE] Run PLASO")
                self.check_docker_image(
                    image_name=self.docker_images["plaso"]["image"],
                    tag=self.docker_images["plaso"]["tag"],
                    logger=self.logger,
                )
                self.generate_mft_timeline(logger=self.logger)
                self.generate_winarts_timeline(logger=self.logger)
        except Exception as ex:
            self.error(f"[KAPE ERROR] {str(ex)}")
            self.info("Exception so kill my running containers")
            self.kill_docker_container(logger=self.logger)
            raise ex
        finally:
            self.info("[KAPE] End processing")
            if self.vhdx_file:
                self.unmountVHDX(logger=self.logger)
