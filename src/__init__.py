import os
import yaml
import json
from slugify import slugify
from src.thirdparty import triageutils as triageutils
from src.thirdparty.logging import get_logger


class BasePlugin(object):
    def __init__(self, config=None):
        if not config:
            self.error("[BasePlugin] Config must not be NONE")
            raise Exception("[BasePlugin] Config must not be NONE")
        self.logger = get_logger(name=config["uuid"])
        self.config = config

        internal_config = triageutils.INTERNAL_CONFIG

        self.timesketch_url = internal_config["general"]["timesketch_url"]
        self.elastic_url = internal_config["general"]["elastic_url"]
        self.logstash_url = internal_config["general"]["logstash_url"]
        self.kibana_url = internal_config["general"]["kibana_url"]

        self.hayabusa_port = internal_config["pipelines"]["hayabusa"]
        self.adtimeline_port = internal_config["pipelines"]["adtimeline"]
        self.iis_port = internal_config["pipelines"]["iis"]
        self.evtxparser_port = internal_config["pipelines"]["evtxparser"]
        self.volatility_port = internal_config["pipelines"]["volatility"]
        self.o365_port = internal_config["pipelines"]["o365"]
        self.raw_json_port = internal_config["pipelines"]["fortinet"]
        self.adaudit_port = internal_config["pipelines"]["adaudit"]
        self.filebeat_port = internal_config["pipelines"]["filebeat"]

        self.orc_port = internal_config["pipelines"]["orc"]
        self.hayabusa_bin_path = internal_config["general"]["hayabusa_bin_path"]
        self.winlogbeat = internal_config["general"]["winlogbeat"]

        self.data_volume = internal_config["volumes"]["data"]

        self.docker_images = internal_config["docker_images"]

        # UAC ARTIFACTS
        self.uac_artifacts = internal_config["artifacts"]

        # PLASO / LOG2TIMELINE
        self.kape_plaso = internal_config["plaso_parsers"]

        # GENERAL
        self.upload_dir = config["general"]["extract"]  # see triage.py:main
        self.hostname = config["general"]["hostname"].lower()
        self.clientname = config["general"]["client"].lower()
        self.timesketch_id = config["general"]["timesketch_id"]

        self.evtx_mapping = self._ParseMapFile()

    def _ParseMapFile(self):
        with open(os.path.join("config", "mapping.json")) as mapp:
            return json.load(mapp)

    def run(self):
        """Main entry point of the plugin"""
        raise NotImplementedError("[BasePlugin] run() needs to be overriden")

    def warning(self, msg):
        """Logs a message at WARNING level"""
        self.logger.warning(msg)

    def error(self, msg):
        """Logs a message at ERROR level"""
        self.logger.error(msg)

    def info(self, msg):
        """Logs a message at INFO level"""
        self.logger.info(msg)

    def debug(self, msg):
        """Logs a message at DEBUG level"""
        self.logger.debug(msg)
