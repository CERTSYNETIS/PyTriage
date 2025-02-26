import subprocess
import os
import json
import asyncio
from src.thirdparty import triageutils as triageutils
from src import BasePlugin


class Plugin(BasePlugin):
    """
    HAYABUSA plugin pour triage
    """

    def __init__(self, conf: dict):
        super().__init__(config=conf)

        if triageutils.directory_exists(
            dir=os.path.join(self.upload_dir, self.hostname, "kape", "EVTX_Orig"),
            logger=self.logger,
        ):
            self.hayabusa_dir = os.path.join(
                self.upload_dir, self.hostname, "kape", "EVTX_Orig"
            )
        elif triageutils.directory_exists(
            dir=os.path.join(self.upload_dir, self.hostname, "generaptor", "EVTX_Orig"),
            logger=self.logger,
        ):
            self.hayabusa_dir = os.path.join(
                self.upload_dir, self.hostname, "generaptor", "EVTX_Orig"
            )
        else:
            self.error("[HAYABUSA] No evtx folder")
            raise Exception("[HAYABUSA] No evtx folder")
        if not len(
            triageutils.search_files(
                src=self.hayabusa_dir, pattern=".evtx", logger=self.logger
            )
        ):
            self.error("[HAYABUSA] No evtx to scan")
            raise Exception("[HAYABUSA] No evtx to scan")
        self.output_json = (
            f"{os.path.join(self.hayabusa_dir,self.clientname)}_HAYABUSA_SIGMA.jsonl"
        )

    @triageutils.LOG
    def exec_hayabusa(self, log_folder=None, logger=None):
        """Exécution du binaire hayabusa sur un dossier

        Args:
            dir (str): optionnel chemin du dossier sur lequel appliquer hayabusa
        Returns:

        """
        try:
            if not log_folder:
                log_folder = self.hayabusa_dir
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
    def send_to_elk(self, logger=None):
        """Fonction qui envoie les résultats hayabusa vers ELK"""
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
            self.error(f"[send_to_elk] {str(e)}")
            raise e

    @triageutils.LOG
    def run(self, logger=None):
        """Fonction principale qui exécute hayabusa

        Args:

        Returns:

        """
        try:
            self.exec_hayabusa(logger=self.logger)
            self.send_to_elk(logger=self.logger)
        except Exception as ex:
            self.error(f"[HAYABUSA] run {str(ex)}")
            raise ex
