import os
import json
from pathlib import Path
from logging import Logger
from src.thirdparty import triageutils as triageutils
from src.thirdparty.wrapper_docker import WrapperDocker
from src import BasePlugin, Status


class Plugin(BasePlugin):
    """
    Volatility3 plugin pour triage
    """

    def __init__(self, conf: dict):
        super().__init__(config=conf)
        self._docker = WrapperDocker(logger=self.logger)
        self.volatility_dir = Path(
            os.path.join(self.upload_dir, self.hostname, "volatility")
        )
        triageutils.create_directory_path(path=self.volatility_dir, logger=self.logger)
        self.volatility_memory_dump = os.path.join(
            self.upload_dir, conf["archive"]["name"]
        )

    @triageutils.LOG
    def volatility_plugin(
        self,
        plugin_name: str,
        logger: Logger,
        extra_cmd: list = [],
        pretty: bool = False,
    ) -> Path:
        """Exécution de plugin volatility3 sur un dump mémoire

        Args:
            plugin_name (str): plugin to execute
            extra_cmd (list): Extra params for plugin
            pretty (bool): Pretty output instead of jsonl
            logger (logger): Logger used by decorator
        Returns:
            result file path (str)
        """
        try:
            render = "jsonl"
            output_file = f"{plugin_name}.jsonl"
            if pretty:
                render = "pretty"
                output_file = f"{plugin_name}.txt"

            cmd = ["-q", "-r", render, "-f", self.volatility_memory_dump, plugin_name]
            cmd.extend(extra_cmd)
            self._docker.image = f'{self.docker_images["volatility3"]["image"]}:{self.docker_images["volatility3"]["tag"]}'
            if not self._docker.is_image_present(name=self._docker.image):
                raise Exception("Image not present")
            self._docker.container = f"{self.uuid}-vol-{plugin_name}"
            self._docker.volumes = [f"{self.data_volume}:/data"]
            with open(
                os.path.join(self.volatility_dir, output_file), "w"
            ) as plugin_results:
                for _result in self._docker.execute_cmd_generator(cmd=cmd):
                    if _result.startswith("{"):
                        plugin_results.write(f"{_result}\n")
            return self.volatility_dir / output_file
        except Exception as ex:
            self.error(f"[volatility_plugin] {ex}")
            raise ex

    @triageutils.LOG
    def volatility_send_results(self, result_file: Path, logger: Logger):
        """Fonction qui envoie les résultats volatility vers ELK"""
        try:
            with open(str(result_file), "r") as jsonl_f:
                json_data = [json.loads(line) for line in jsonl_f]
                if not json_data:
                    self.logger.error(
                        "[volatility_send_results] Nothing to send -- exit"
                    )
                    return
                ip = self.logstash_url
                if ip.startswith("http"):
                    ip = self.logstash_url.split("//")[1]
                extrafields = dict()
                extrafields["csirt"] = dict()
                extrafields["csirt"]["client"] = self.clientname.lower()
                extrafields["csirt"]["application"] = "volatility"
                extrafields["csirt"]["hostname"] = self.hostname.lower()
                triageutils.send_data_to_elk(
                    data=json_data,
                    ip=ip,
                    port=self.volatility_port,
                    logger=self.logger,
                    extrafields=extrafields,
                )
        except Exception as e:
            self.error(f"[volatility_send_results] {str(e)}")
            raise e

    @triageutils.LOG
    def run(self, logger=None):
        """Fonction principale qui exécute les plugins volatility

        Args:

        Returns:

        """
        try:
            _exceptions = list()
            self.update_workflow_status(
                plugin="volatility", module="plugin", status=Status.STARTED
            )
            try:
                if self.config["run"]["volatility"]["pslist"]:
                    self.info("[volatility] Run pslist")
                    self.update_workflow_status(
                        plugin="volatility", module="pslist", status=Status.STARTED
                    )
                    res_file = self.volatility_plugin(
                        plugin_name="windows.pslist", logger=self.logger
                    )
                    if self.is_logstash_active:
                        self.volatility_send_results(
                            result_file=res_file, logger=self.logger
                        )
                    self.update_workflow_status(
                        plugin="volatility", module="pslist", status=Status.FINISHED
                    )
            except Exception as ex:
                self.error(f"[volatility ERROR] {str(ex)}")
                _exceptions.append(str(ex))
                self.update_workflow_status(
                    plugin="volatility", module="pslist", status=Status.ERROR
                )
            try:
                if self.config["run"]["volatility"]["pstree"]:
                    self.info("[volatility] Run pstree")
                    self.update_workflow_status(
                        plugin="volatility", module="pstree", status=Status.STARTED
                    )
                    res_file = self.volatility_plugin(
                        plugin_name="windows.pstree", logger=self.logger
                    )
                    if self.is_logstash_active:
                        self.volatility_send_results(
                            result_file=res_file, logger=self.logger
                        )
                    self.update_workflow_status(
                        plugin="volatility", module="pstree", status=Status.FINISHED
                    )
            except Exception as ex:
                self.error(f"[volatility ERROR] {str(ex)}")
                _exceptions.append(str(ex))
                self.update_workflow_status(
                    plugin="volatility", module="pstree", status=Status.ERROR
                )
            try:
                if self.config["run"]["volatility"]["netscan"]:
                    self.info("[volatility] Run netscan")
                    self.update_workflow_status(
                        plugin="volatility", module="netscan", status=Status.STARTED
                    )
                    res_file = self.volatility_plugin(
                        plugin_name="windows.netscan", logger=self.logger
                    )
                    if self.is_logstash_active:
                        self.volatility_send_results(
                            result_file=res_file, logger=self.logger
                        )
                    self.update_workflow_status(
                        plugin="volatility", module="netscan", status=Status.FINISHED
                    )
            except Exception as ex:
                self.error(f"[volatility ERROR] {str(ex)}")
                _exceptions.append(str(ex))
                self.update_workflow_status(
                    plugin="volatility", module="netscan", status=Status.ERROR
                )
            try:
                if self.config["run"]["volatility"]["netstat"]:
                    self.info("[volatility] Run netstat")
                    self.update_workflow_status(
                        plugin="volatility", module="netstat", status=Status.STARTED
                    )
                    res_file = self.volatility_plugin(
                        plugin_name="windows.netstat", logger=self.logger
                    )
                    if self.is_logstash_active:
                        self.volatility_send_results(
                            result_file=res_file, logger=self.logger
                        )
                    self.update_workflow_status(
                        plugin="volatility", module="netstat", status=Status.FINISHED
                    )
            except Exception as ex:
                self.error(f"[volatility ERROR] {str(ex)}")
                _exceptions.append(str(ex))
                self.update_workflow_status(
                    plugin="volatility", module="netstat", status=Status.ERROR
                )
            self.update_workflow_status(
                plugin="volatility", module="plugin", status=Status.FINISHED
            )
            if len(_exceptions) > 0:
                raise Exception(str(_exceptions))
        except Exception as ex:
            self.error(f"[volatility] run {str(ex)}")
            self.update_workflow_status(
                plugin="volatility", module="plugin", status=Status.ERROR
            )
            raise ex
        finally:
            self._docker.kill_containers_by_name(name=self.uuid)
            self.info("[volatility] End processing")
