import os
import json
import re
import yaml
from pathlib import Path
from logging import Logger
from src.thirdparty import triageutils as triageutils
from src.thirdparty.ParseEVTX import ParseEVTX
from src.thirdparty.wrapper_docker import WrapperDocker
from src import BasePlugin, Status


class Plugin(BasePlugin):
    """
    Standalone plugin pour triage
    Send custom json file to ELK
    with some params
    """

    def __init__(self, conf: dict):
        super().__init__(config=conf)
        self._docker = WrapperDocker(logger=self.logger)
        self.standalone_input_file = os.path.join(
            self.upload_dir, conf["archive"]["name"]
        )
        self.standalone_dir = os.path.join(self.upload_dir, self.hostname, "standalone")
        triageutils.create_directory_path(path=self.standalone_dir, logger=self.logger)

    @triageutils.LOG
    def standalone_hayabusa(self, logger: Logger):
        """Fonction qui envoie les résultats hayabusa vers ELK"""
        try:
            with open(self.standalone_input_file, "r") as jsonl_f:
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
                                f"[standalone_hayabusa] Failed to change values type of AllFieldInfo: {haya_error}"
                            )
                ip = self.logstash_url
                if ip.startswith("http"):
                    ip = self.logstash_url.split("//")[1]
                extrafields = dict()
                extrafields["csirt"] = dict()
                extrafields["csirt"]["client"] = self.clientname.lower()
                extrafields["csirt"]["application"] = "alerts"
                extrafields["csirt"]["hostname"] = self.hostname.lower()
                _event_sent = triageutils.send_data_to_elk(
                    data=json_data,
                    ip=ip,
                    port=self.hayabusa_port,
                    logger=self.logger,
                    extrafields=extrafields,
                )
            # Send analytics
            if self.is_logstash_active:
                self.standalone_input_file = Path(self.standalone_input_file)
                _file_infos = triageutils.get_file_informations(
                    filepath=self.standalone_input_file
                )
                _analytics = triageutils.generate_analytics(logger=self.logger)
                _analytics["log"]["file"]["eventcount"] = len(json_data)
                _analytics["log"]["file"]["eventsent"] = _event_sent
                _analytics["log"]["file"]["path"] = self.standalone_input_file.name
                _analytics["log"]["file"]["size"] = _file_infos.get("fileSize", 0)
                _analytics["log"]["file"]["lastaccessed"] = _file_infos.get(
                    "lastAccessTime", 0
                )
                _analytics["log"]["file"]["creation"] = _file_infos.get(
                    "creationTime", 0
                )
                _analytics["csirt"]["client"] = self.clientname
                _analytics["csirt"]["hostname"] = self.hostname
                _analytics["csirt"]["application"] = "standalone_hayabusa"
                triageutils.send_data_to_elk(
                    data=_analytics,
                    ip=ip,
                    port=self.selfassessment_port,
                    logger=self.logger,
                )
        except Exception as e:
            self.error(f"[standalone_hayabusa] {str(e)}")
            raise e

    @triageutils.LOG
    def standalone_extract_zip(
        self, archive: str | Path, dest: str | Path, logger: Logger
    ):
        """Extrait tous les fichiers de l'archive ZIP contenant les EVTX
        Args:
            archive (str): optionnel chemin complet du fichier zip
            dest (str): optionnel chemin complet de décompression de l'archive
        """
        try:
            if not archive:
                raise Exception("no input archive")
            if not dest:
                raise Exception("no destination folder")
            self.info(f"[standalone_extract_zip] Zip file: {archive}")
            self.info(f"[standalone_extract_zip] Dest folder: {dest}")
            triageutils.extract_zip_archive(
                archive=archive,
                dest=dest,
                logger=self.logger,
            )
        except Exception as ex:
            self.logger.error(f"[standalone_extract_zip] {ex}")
            raise ex

    @triageutils.LOG
    def standalone_get_evtx(self, evtx_folder: str | Path, logger: Logger) -> list:
        """Retourne les evtx présents dans le dossier vers le dossier partagé.
        Args:
            evtx_folder (str): optionnel chemin du dossier contenant les fichiers evtx si pas de dossier, il cherche dans tout le vhdx
        Returns:
            un tableau contenant le nom de tous les fichiers trouvés
        """
        try:
            records = []
            if not evtx_folder:
                raise Exception("no EVTX folder")
            records.extend(
                triageutils.search_files_by_extension(
                    dir=evtx_folder, extension=".evtx", logger=self.logger
                )
            )
            return records
        except Exception as ex:
            self.logger.error(f"[standalone_get_evtx] {ex}")
            raise ex

    @triageutils.LOG
    def standalone_winlogbeat(self, evtx_folder: Path, logger: Logger):
        """Copie les evtx vers le dossier partagé sur la VM Winlogbeat.
        Args:
            evtx_folder (Path)
        Returns:
            result (bool): True or False
        """
        try:
            win_log_path = os.path.join(self.winlogbeat, self.clientname, self.hostname)
            triageutils.create_directory_path(path=win_log_path, logger=self.logger)
            for _f in evtx_folder.rglob("*.evtx"):
                triageutils.copy_file(
                    src=_f, dst=win_log_path, overwrite=True, logger=self.logger
                )
            return True
        except Exception as ex:
            self.error(f"[generaptor_evtx_winlogbeat] {ex}")
            return False

    @triageutils.LOG
    def standalone_fortinet_filebeat(self, log_folder: str | Path, logger: Logger):
        """Fonction qui exeécute filebeat sur logs fortinet et les envoie vers ELK"""
        try:
            ip = self.logstash_url
            if ip.startswith("http"):
                ip = self.logstash_url.split("//")[1]
            _config = triageutils.generate_fortinet_filebeat_config(
                ip=ip,
                port=self.filebeat_port,
                client=self.clientname.lower(),
                hostname=self.hostname.lower(),
                logger=self.logger,
            )
            new_config = Path(self.standalone_dir) / Path("filebeat.docker.yml")
            with open(new_config.as_posix(), "w") as file:
                yaml.dump(_config, file, sort_keys=False)
            voldisk = [
                f"{log_folder}:/fortinet",
                f"{new_config}:/usr/share/filebeat/filebeat.yml:ro",
            ]
            cmd = ["filebeat", "-e", "--once", "--strict.perms=false"]
            self._docker.image = f'{self.docker_images["filebeat"]["image"]}:{self.docker_images["filebeat"]["tag"]}'
            if not self._docker.is_image_present(name=self._docker.image):
                raise Exception("Image not present")
            self._docker.container = f"{self.uuid}-fortinet"
            self._docker.volumes = voldisk
            self._docker.execute_cmd(cmd=cmd)

        except Exception as e:
            self.error(f"[standalone_fortinet_log] {str(e)}")
            raise e

    @triageutils.LOG
    def standalone_forcepoint_log(self, logs: list, logger: Logger):
        """Fonction qui envoie les résultats de parsing de logs forcepoint vers ELK"""
        try:
            total = len(logs)
            count = 0
            for log_file in logs:
                _data_to_send = []
                try:
                    self.info(f"[standalone_forcepoint_log] Parsing File: {log_file}")
                    with open(log_file) as f:
                        count += 1
                        lines = f.readlines()
                        for line in lines:
                            keys = re.findall("(\w+)=", line)
                            _v = re.findall('=(?:"([^"]*)"|(\S+))', line)
                            vals = ["".join(x) for x in _v]
                            try:
                                _data = {
                                    keys[i]: vals[i].replace('"', "").strip()
                                    for i in range(len(keys))
                                }
                            except Exception as _error:
                                _data = dict()
                                self.error(
                                    f"[standalone_forcepoint_log] _data error : {_error}"
                                )
                            for _k in [
                                "ICMP_CODE",
                                "ICMP_TYPE",
                                "ICMP_ID",
                                "Sport",
                                "Dport",
                                "PROTOCOL",
                            ]:
                                if _k in keys:
                                    try:
                                        _data[_k] = int(_data[_k])
                                    except Exception as _error:
                                        _data[_k] = 0
                                        self.error(
                                            f"[standalone_forcepoint_log] int error : {_error}"
                                        )
                            _data_to_send.append(_data)
                        self.info(
                            f"[standalone_forcepoint_log] send file {count}/{total}"
                        )
                except Exception as _error:
                    self.error(f"[standalone_forcepoint_log] : {_error}")
                ip = self.logstash_url
                if ip.startswith("http"):
                    ip = self.logstash_url.split("//")[1]
                extrafields = dict()
                extrafields["csirt"] = dict()
                extrafields["csirt"]["client"] = self.clientname.lower()
                extrafields["csirt"]["application"] = "forcepoint"
                extrafields["csirt"]["hostname"] = self.hostname.lower()
                triageutils.send_data_to_elk(
                    data=_data_to_send,
                    ip=ip,
                    port=self.raw_json_port,
                    logger=self.logger,
                    extrafields=extrafields,
                )
        except Exception as e:
            self.error(f"[standalone_forcepoint_log] {str(e)}")
            raise e

    @triageutils.LOG
    def standalone_get_log_files(self, log_folder: str | Path, logger: Logger) -> list:
        """Retourne les log présents dans le dossier.
        Args:
            log_folder (str): chemin du dossier contenant les fichiers log
        Returns:
            un tableau contenant le nom de tous les fichiers trouvés
        """
        try:
            records = []
            records.extend(
                triageutils.search_files(
                    src=log_folder, pattern=".log", logger=self.logger
                )
            )
            records.extend(
                triageutils.search_files(
                    src=log_folder, pattern=".txt", logger=self.logger
                )
            )
            return records
        except Exception as ex:
            self.logger.error(f"[standalone_get_log_files] {ex}")
            raise ex

    @triageutils.LOG
    def run(self, logger=None):
        """Fonction principale qui exécute l'export vers ELK du fichier donné en source et du plugin choisi
            Hayabusa
            Winlogbeat
        Args:

        Returns:

        """
        try:
            if self.config["run"]["standalone"]["hayabusa"] and self.is_logstash_active:
                try:
                    self.update_workflow_status(
                        plugin="standalone", module="hayabusa", status=Status.STARTED
                    )
                    self.standalone_hayabusa(logger=self.logger)
                    self.update_workflow_status(
                        plugin="standalone", module="hayabusa", status=Status.FINISHED
                    )
                except Exception as ex:
                    self.error(f"[Standalone ERROR] {str(ex)}")
                    self.update_workflow_status(
                        plugin="standalone", module="hayabusa", status=Status.ERROR
                    )
            elif (
                self.config["run"]["standalone"]["winlogbeat"]
                and self.is_winlogbeat_active
            ):
                try:
                    self.update_workflow_status(
                        plugin="standalone", module="winlogbeat", status=Status.STARTED
                    )
                    zip_destination = Path(os.path.join(self.standalone_dir, "extract"))
                    triageutils.create_directory_path(
                        path=zip_destination, logger=self.logger
                    )
                    self.standalone_extract_zip(
                        archive=self.standalone_input_file,
                        dest=zip_destination,
                        logger=self.logger,
                    )
                    self.config["general"]["extracted_zip"] = f"{zip_destination}"
                    self.update_config_file(data=self.config)
                    self.standalone_winlogbeat(
                        evtx_folder=zip_destination, logger=self.logger
                    )
                    self.update_workflow_status(
                        plugin="standalone", module="winlogbeat", status=Status.FINISHED
                    )
                except Exception as ex:
                    self.error(f"[Standalone ERROR] {str(ex)}")
                    self.update_workflow_status(
                        plugin="standalone", module="winlogbeat", status=Status.ERROR
                    )
            elif self.config["run"]["standalone"]["evtx"]:
                try:
                    self.update_workflow_status(
                        plugin="standalone", module="evtx", status=Status.STARTED
                    )
                    zip_destination = Path(os.path.join(self.standalone_dir, "extract"))
                    triageutils.create_directory_path(
                        path=zip_destination, logger=self.logger
                    )
                    evtx_destination = os.path.join(self.standalone_dir, "EVTX")
                    triageutils.create_directory_path(
                        path=evtx_destination, logger=self.logger
                    )
                    self.standalone_extract_zip(
                        archive=self.standalone_input_file,
                        dest=zip_destination,
                        logger=self.logger,
                    )
                    self.config["general"]["extracted_zip"] = f"{zip_destination}"
                    self.update_config_file(data=self.config)
                    _ip = self.logstash_url
                    if _ip.startswith("http"):
                        _ip = self.logstash_url.split("//")[1]
                    for _f in zip_destination.rglob("*.evtx"):
                        _p = ParseEVTX(
                            evtxfilepath=_f,
                            ip=_ip,
                            port=self.evtxparser_port,
                            client=self.clientname,
                            hostname=self.hostname,
                            mapping=self.evtx_mapping,
                            output_folder=Path(evtx_destination),
                            logstash_is_active=self.is_logstash_active,
                            logger=self.logger,
                        )
                        self.info(f"[Standalone] Parse: {_f}")
                        _res = _p.parse_evtx()
                        self.info(f"[Standalone] Results: {_res}")
                        # send analytics info
                        if self.is_logstash_active:
                            _file_infos = triageutils.get_file_informations(filepath=_f)
                            _analytics = triageutils.generate_analytics(
                                logger=self.logger
                            )
                            _analytics["log"]["file"]["eventcount"] = _res.get(
                                "nb_events_read", 0
                            )
                            _analytics["log"]["file"]["eventsent"] = _res.get(
                                "nb_events_sent", 0
                            )
                            _analytics["log"]["file"]["path"] = _res.get("file", "")
                            _analytics["log"]["file"]["size"] = _file_infos.get(
                                "fileSize", 0
                            )
                            _analytics["log"]["file"]["lastaccessed"] = _file_infos.get(
                                "lastAccessTime", 0
                            )
                            _analytics["log"]["file"]["creation"] = _file_infos.get(
                                "creationTime", 0
                            )
                            _analytics["csirt"]["client"] = self.clientname
                            _analytics["csirt"]["hostname"] = self.hostname
                            _analytics["csirt"]["application"] = "standalone_parse_evtx"
                            triageutils.send_data_to_elk(
                                data=_analytics,
                                ip=_ip,
                                port=self.selfassessment_port,
                                logger=self.logger,
                            )
                    self.update_workflow_status(
                        plugin="standalone", module="evtx", status=Status.FINISHED
                    )
                except Exception as ex:
                    self.error(f"[Standalone ERROR] {str(ex)}")
                    self.update_workflow_status(
                        plugin="standalone", module="evtx", status=Status.ERROR
                    )
            elif (
                self.config["run"]["standalone"]["fortinet"] and self.is_logstash_active
            ):
                try:
                    self.update_workflow_status(
                        plugin="standalone", module="fortinet", status=Status.STARTED
                    )
                    zip_destination = os.path.join(self.standalone_dir, "Fortinet")
                    triageutils.create_directory_path(
                        path=zip_destination, logger=self.logger
                    )
                    self.standalone_extract_zip(
                        archive=self.standalone_input_file,
                        dest=zip_destination,
                        logger=self.logger,
                    )
                    self.config["general"]["extracted_zip"] = f"{zip_destination}"
                    self.update_config_file(data=self.config)
                    self.standalone_fortinet_filebeat(
                        log_folder=zip_destination, logger=self.logger
                    )
                    self.update_workflow_status(
                        plugin="standalone", module="fortinet", status=Status.FINISHED
                    )
                except Exception as ex:
                    self.error(f"[Standalone ERROR] {str(ex)}")
                    self.update_workflow_status(
                        plugin="standalone", module="fortinet", status=Status.ERROR
                    )
            elif (
                self.config["run"]["standalone"]["forcepoint"]
                and self.is_logstash_active
            ):
                try:
                    self.update_workflow_status(
                        plugin="standalone", module="forcepoint", status=Status.STARTED
                    )
                    zip_destination = os.path.join(self.standalone_dir, "Forcepoint")
                    triageutils.create_directory_path(
                        path=zip_destination, logger=self.logger
                    )
                    self.standalone_extract_zip(
                        archive=self.standalone_input_file,
                        dest=zip_destination,
                        logger=self.logger,
                    )
                    self.config["general"]["extracted_zip"] = f"{zip_destination}"
                    self.update_config_file(data=self.config)
                    forcepoint_logs = self.standalone_get_log_files(
                        log_folder=zip_destination, logger=self.logger
                    )
                    self.standalone_forcepoint_log(
                        logs=forcepoint_logs, logger=self.logger
                    )
                    self.update_workflow_status(
                        plugin="standalone", module="forcepoint", status=Status.FINISHED
                    )
                except Exception as ex:
                    self.error(f"[Standalone ERROR] {str(ex)}")
                    self.update_workflow_status(
                        plugin="standalone", module="forcepoint", status=Status.ERROR
                    )
        except Exception as ex:
            self.error(f"[Standalone] run {str(ex)}")
            raise ex
        finally:
            self._docker.kill_containers_by_name(name=self.uuid)
            self.info("[Standalone] End processing")
