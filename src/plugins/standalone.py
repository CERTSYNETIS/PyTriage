import os
import json
import re
from pathlib import Path
from src.thirdparty import triageutils as triageutils
from src.thirdparty.ParseEVTX import ParseEVTX
from src import BasePlugin


class Plugin(BasePlugin):
    """
    Standalone plugin pour triage
    Send custom json file to ELK
    with some params
    """

    def __init__(self, conf: dict):
        super().__init__(config=conf)
        self.standalone_input_file = os.path.join(
            self.upload_dir, conf["archive"]["name"]
        )
        self.standalone_dir = os.path.join(self.upload_dir, self.hostname, "standalone")
        triageutils.create_directory_path(path=self.standalone_dir, logger=self.logger)

    @triageutils.LOG
    def standalone_hayabusa(self, logger=None):
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
                triageutils.send_data_to_elk(
                    data=json_data,
                    ip=ip,
                    port=self.hayabusa_port,
                    logger=self.logger,
                    extrafields=extrafields,
                )
        except Exception as e:
            self.error(f"[standalone_hayabusa] {str(e)}")
            raise e

    @triageutils.LOG
    def standalone_extract_zip(self, archive=None, dest=None, logger=None):
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
    def standalone_get_evtx(self, evtx_folder=None, logger=None) -> list:
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
                triageutils.search_files(
                    src=evtx_folder, pattern=".evtx", logger=self.logger
                )
            )
            return records
        except Exception as ex:
            self.logger.error(f"[standalone_get_evtx] {ex}")
            raise ex

    @triageutils.LOG
    def standalone_winlogbeat(self, evtx_logs=[], logger=None):
        """Copie les evtx vers le dossier partagé sur la VM Winlogbeat.
        Args:
            evtx_logs (list): Liste contenant les chemins des fichiers de log
        Returns:
            result (bool): True or False
        """
        result = True
        if not len(evtx_logs):
            self.error(f"[standalone_winlogbeat] No EVTX logs to send")
            return False
        try:
            win_log_path = os.path.join(self.winlogbeat, self.clientname, self.hostname)
            if triageutils.create_directory_path(path=win_log_path, logger=self.logger):
                self.info(f"[standalone_winlogbeat] WinLogBeat created: {win_log_path}")
                result &= triageutils.copy_files(
                    src=evtx_logs, dst=win_log_path, overwrite=True, logger=self.logger
                )
        except Exception as ex:
            self.error(f"[standalone_winlogbeat] {ex}")
        self.info(f"[standalone_winlogbeat] result: {result}")
        return result

    @triageutils.LOG
    def standalone_fortinet_log(self, logs=[], logger=None):
        """Fonction qui envoie les résultats de parsing de logs fortinet vers ELK"""
        try:
            total = len(logs)
            count = 0
            for log_file in logs:
                _data_to_send = []
                try:
                    self.info(f"[standalone_fortinet_log] Parsing File: {log_file}")
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
                                self.error(
                                    f"[standalone_fortinet_log] _data error : {_error}"
                                )
                            for _k in [
                                "transport",
                                "duration",
                                "sentbyte",
                                "rcvdbyte",
                                "sentpkt",
                                "rcvdpkt",
                                "sentdelta",
                                "rcvddelta",
                                "proto",
                            ]:
                                if _k in keys:
                                    try:
                                        _data[_k] = int(_data[_k])
                                    except Exception as _error:
                                        _data[_k] = 0
                                        self.error(
                                            f"[standalone_fortinet_log] int error : {_error}"
                                        )
                            _data_to_send.append(_data)
                        self.info(
                            f"[standalone_fortinet_log] send file {count}/{total}"
                        )
                except Exception as _error:
                    self.error(f"[standalone_fortinet_log] : {_error}")
                ip = self.logstash_url
                if ip.startswith("http"):
                    ip = self.logstash_url.split("//")[1]
                extrafields = dict()
                extrafields["csirt"] = dict()
                extrafields["csirt"]["client"] = self.clientname.lower()
                extrafields["csirt"]["application"] = "fortinet"
                extrafields["csirt"]["hostname"] = self.hostname.lower()
                triageutils.send_data_to_elk(
                    data=_data_to_send,
                    ip=ip,
                    port=self.raw_json_port,
                    logger=self.logger,
                    extrafields=extrafields,
                )
        except Exception as e:
            self.error(f"[standalone_fortinet_log] {str(e)}")
            raise e

    @triageutils.LOG
    def standalone_get_log_files(self, log_folder=None, logger=None) -> list:
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
            if self.config["run"]["standalone"]["hayabusa"]:
                self.standalone_hayabusa(logger=self.logger)
            elif self.config["run"]["standalone"]["winlogbeat"]:
                zip_destination = os.path.join(self.standalone_dir, "extract")
                triageutils.create_directory_path(
                    path=zip_destination, logger=self.logger
                )
                self.standalone_extract_zip(
                    archive=self.standalone_input_file,
                    dest=zip_destination,
                    logger=self.logger,
                )
                evtx_logs = self.standalone_get_evtx(
                    evtx_folder=zip_destination, logger=self.logger
                )
                self.standalone_winlogbeat(evtx_logs=evtx_logs, logger=self.logger)
            elif self.config["run"]["standalone"]["evtx"]:
                zip_destination = os.path.join(self.standalone_dir, "extract")
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
                _ip = self.logstash_url
                if _ip.startswith("http"):
                    _ip = self.logstash_url.split("//")[1]
                for _f in triageutils.search_files_generator(
                    src=zip_destination, pattern=".evtx"
                ):
                    _p = ParseEVTX(
                        evtxfilepath=_f,
                        ip=_ip,
                        port=self.evtxparser_port,
                        client=self.clientname,
                        hostname=self.hostname,
                        mapping=self.evtx_mapping,
                        output_folder=Path(evtx_destination),
                        logger=self.logger,
                    )
                    _res = _p.parse_evtx()
                    self.info(f"[Standalone] {_res}")
            elif self.config["run"]["standalone"]["fortinet"]:
                zip_destination = os.path.join(self.standalone_dir, "LOGS")
                triageutils.create_directory_path(
                    path=zip_destination, logger=self.logger
                )
                self.standalone_extract_zip(
                    archive=self.standalone_input_file,
                    dest=zip_destination,
                    logger=self.logger,
                )
                forti_logs = self.standalone_get_log_files(
                    log_folder=zip_destination, logger=self.logger
                )
                self.standalone_fortinet_log(logs=forti_logs)
        except Exception as ex:
            self.error(f"[Standalone] run {str(ex)}")
            raise ex
