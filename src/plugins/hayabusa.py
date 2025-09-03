import subprocess
import os
import json
from pathlib import Path
from src.thirdparty import triageutils as triageutils
from src import BasePlugin, Status


class Plugin(BasePlugin):
    """
    HAYABUSA plugin pour triage
    """

    def __init__(self, conf: dict):
        super().__init__(config=conf)
        try:
            _evtx_folder = next(
                triageutils.search_files_by_extension_generator(
                    src=Path(conf["general"]["extracted_zip"]).parent,
                    extension=".evtx",
                    logger=self.logger,
                )
            )
            if _evtx_folder:
                self.evtx_dir = _evtx_folder.parent
                self.hayabusa_dir = Path(
                    os.path.join(self.upload_dir, self.hostname, "Hayabusa")
                )
                triageutils.create_directory_path(
                    path=self.hayabusa_dir, logger=self.logger
                )
            else:
                self.error("[HAYABUSA] No evtx folder")
                raise Exception("[HAYABUSA] No evtx folder")
            self.output_json = f"{self.hayabusa_dir}/HAYABUSA_SIGMA.jsonl"
        except Exception as ex:
            self.error(f"[init] {ex}")
            raise ex

    @triageutils.LOG
    def exec_hayabusa(self, log_folder: Path, logger=None):
        """Exécution du binaire hayabusa sur un dossier

        Args:
            dir (str): optionnel chemin du dossier sur lequel appliquer hayabusa
        Returns:

        """
        try:
            cmd = [
                self.hayabusa_bin_path,
                "json-timeline",
                "-d",
                log_folder,
                "-p",
                "all-field-info-verbose",
                "-ULwqNC",
                "-o",
                self.output_json,
            ]
            p = subprocess.Popen(
                cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=os.environ
            )
            (output, err) = p.communicate()
            p_status = p.wait()

            # self.info(f"[hayabusa] output: {output}")
            self.info(f"[hayabusa] error: {err}")
            self.info(f"[hayabusa] status: {p_status}")
            if not triageutils.file_exists(file=self.output_json, logger=self.logger):
                self.error("[ERROR] hayabusa no output file present")
                raise Exception("[ERROR] hayabusa no output file present")
            self.info(f"[HAYABUSA] status: {p_status}")
        except Exception as ex:
            self.error(f"[HAYABUSA] {ex}")
            raise ex

    @triageutils.LOG
    def send_to_elk(self, logger=None) -> int:
        """
        Fonction qui envoie les résultats hayabusa vers ELK
        Return:
            number of event sent (int)
        """
        try:
            with open(self.output_json, "r") as jsonl_f:
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
                                f"[send_to_elk] Failed to change values type of AllFieldInfo: {haya_error}"
                            )
                if self.is_logstash_active:
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
                    return _event_sent
                return 0
        except Exception as e:
            self.error(f"[send_to_elk] {str(e)}")
            raise e

    @triageutils.LOG
    def send_analytics_to_elk(self, event_sent: int, logger=None):
        try:
            if self.is_logstash_active:
                _total_events = 0
                ip = self.logstash_url
                if ip.startswith("http"):
                    ip = self.logstash_url.split("//")[1]
                with open(self.output_json, "r") as jsonl_f:
                    _total_events = len(jsonl_f.readlines())
                self.output_json = Path(self.output_json)
                _file_infos = triageutils.get_file_informations(
                    filepath=self.output_json
                )
                _analytics = triageutils.generate_analytics(logger=self.logger)
                _analytics["log"]["file"]["eventcount"] = _total_events
                _analytics["log"]["file"]["eventsent"] = event_sent
                _analytics["log"]["file"]["path"] = self.output_json.name
                _analytics["log"]["file"]["size"] = _file_infos.get("fileSize", 0)
                _analytics["log"]["file"]["lastaccessed"] = _file_infos.get(
                    "lastAccessTime", 0
                )
                _analytics["log"]["file"]["creation"] = _file_infos.get(
                    "creationTime", 0
                )
                _analytics["csirt"]["client"] = self.clientname
                _analytics["csirt"]["hostname"] = self.hostname
                _analytics["csirt"]["application"] = "hayabusa"
                triageutils.send_data_to_elk(
                    data=_analytics,
                    ip=ip,
                    port=self.selfassessment_port,
                    logger=self.logger,
                )
        except Exception as ex:
            self.error(f"[send_analytics_to_elk] {ex}")
            raise ex

    @triageutils.LOG
    def run(self, logger=None):
        """Fonction principale qui exécute hayabusa

        Args:

        Returns:

        """
        try:
            self.update_workflow_status(plugin="hayabusa", status=Status.STARTED)
            self.exec_hayabusa(log_folder=self.evtx_dir, logger=self.logger)
            if self.is_logstash_active:
                _event_sent = self.send_to_elk(logger=self.logger)
                self.send_analytics_to_elk(event_sent=_event_sent, logger=self.logger)
            self.update_workflow_status(plugin="hayabusa", status=Status.FINISHED)
        except Exception as ex:
            self.error(f"[HAYABUSA] run {str(ex)}")
            self.update_workflow_status(plugin="hayabusa", status=Status.ERROR)
            raise ex
