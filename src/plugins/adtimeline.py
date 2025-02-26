import os
import json
import asyncio
from src.thirdparty import triageutils as triageutils
from src import BasePlugin


class Plugin(BasePlugin):
    """
    ADTimeline plugin pour triage
    """

    def __init__(self, conf: dict):
        super().__init__(config=conf)
        self.adtimeline_csv_file = os.path.join(
            self.upload_dir, conf["archive"]["name"]
        )
        self.adtimeline_dir = os.path.join(self.upload_dir, self.hostname, "ADTimeline")
        self.adtimeline_json_file = os.path.join(
            self.adtimeline_dir, f"ADTimeline_{self.clientname}.json"
        )
        triageutils.create_directory_path(path=self.adtimeline_dir, logger=self.logger)

    @triageutils.LOG
    def send_to_elk(self, json_data: list = [], logger=None):
        """Fonction qui envoie les résultats ADTimeline vers ELK"""
        try:
            ip = self.logstash_url
            if ip.startswith("http"):
                ip = self.logstash_url.split("//")[1]
            extrafields = dict()
            extrafields["csirt"] = dict()
            extrafields["csirt"]["client"] = self.clientname.lower()
            extrafields["csirt"]["application"] = "adtimeline"
            extrafields["csirt"]["hostname"] = self.hostname.lower()
            triageutils.send_data_to_elk(
                data=json_data,
                ip=ip,
                port=self.adtimeline_port,
                logger=self.logger,
                extrafields=extrafields,
            )
        except Exception as e:
            self.error(f"[send_to_elk] {str(e)}")
            raise e

    @triageutils.LOG
    def run(self, logger=None):
        """Fonction principale qui exécute l'export ADTimeline vers ELK

        Args:

        Returns:

        """
        try:
            extrafields = dict()
            extrafields["csirt"] = dict()
            extrafields["csirt"]["client"] = self.clientname.lower()
            extrafields["csirt"]["application"] = "adtimeline"
            res = triageutils.csv_to_json(
                csvFilePath=self.adtimeline_csv_file,
                jsonFilePath=self.adtimeline_json_file,
                writeToFile=True,
                extrafields=extrafields,
                logger=self.logger,
            )
            self.send_to_elk(json_data=res, logger=self.logger)
        except Exception as ex:
            self.error(f"[ADTimeline] run {str(ex)}")
            raise ex
