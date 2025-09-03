import os
import json
from src.thirdparty import triageutils as triageutils
from src import BasePlugin, Status
import docker


class Plugin(BasePlugin):
    """
    Volatility3 plugin pour triage
    """

    def __init__(self, conf: dict):
        super().__init__(config=conf)
        self.volatility_dir = os.path.join(self.upload_dir, self.hostname, "volatility")
        triageutils.create_directory_path(path=self.volatility_dir, logger=self.logger)
        self.volatility_memory_dump = os.path.join(
            self.upload_dir, conf["archive"]["name"]
        )

    @triageutils.LOG
    def check_docker_image(
        self,
        image_name="volatility3",
        tag="2.5.0",
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
    def volatility_plugin(
        self,
        plugin_name: str = "windows.pslist",
        extra_cmd: list = [],
        pretty: bool = False,
        logger=None,
    ) -> str:
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
            self.info(f"[volatility_plugin] Run Volatitlity plugin: {plugin_name}")
            _docker = docker.from_env()
            render = "jsonl"
            output_file = f"{plugin_name}.jsonl"
            if pretty:
                render = "pretty"
                output_file = f"{plugin_name}.txt"

            cmd = ["-q", "-r", render, "-f", self.volatility_memory_dump, plugin_name]
            cmd.extend(extra_cmd)
            container = _docker.containers.run(
                image=f'{self.docker_images["volatility3"]["image"]}:{self.docker_images["volatility3"]["tag"]}',
                auto_remove=True,
                detach=True,
                command=cmd,
                volumes=[f"{self.data_volume}:/data"],
                stderr=True,
                stdout=True,
                name=f"{self.clientname}-{self.hostname}-volatility-{plugin_name}",
            )
            # container.wait()
            logs = container.logs(stdout=True, stderr=True)
            with open(
                os.path.join(self.volatility_dir, output_file), "w"
            ) as plugin_results:
                plugin_results.write("".join(logs[2:]))
            return os.path.join(self.volatility_dir, output_file)
        except Exception as ex:
            self.error(f"[volatility_plugin] {ex}")
            raise ex

    @triageutils.LOG
    def volatility_send_results(self, result_file=None, logger=None):
        """Fonction qui envoie les résultats volatility vers ELK"""
        try:
            with open(result_file, "r") as jsonl_f:
                json_data = [json.loads(line) for line in jsonl_f]
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
            self.update_workflow_status(
                plugin="volatility", module="plugin", status=Status.STARTED
            )
            self.check_docker_image(
                image_name=self.docker_images["volatility3"]["image"],
                tag=self.docker_images["volatility3"]["tag"],
                logger=self.logger,
            )
            try:
                self.update_workflow_status(
                    plugin="volatility", module="pslist", status=Status.STARTED
                )
                if self.config["run"]["volatility"]["pslist"]:
                    res_file = self.volatility_plugin(
                        plugin_name="windows.pslist", logger=self.logger
                    )
                    self.volatility_send_results(
                        result_file=res_file, logger=self.logger
                    )
                self.update_workflow_status(
                    plugin="volatility", module="pslist", status=Status.FINISHED
                )
            except Exception as ex:
                self.error(f"[volatility ERROR] {str(ex)}")
                self.update_workflow_status(
                    plugin="volatility", module="pslist", status=Status.ERROR
                )
            try:
                self.update_workflow_status(
                    plugin="volatility", module="pstree", status=Status.STARTED
                )
                if self.config["run"]["volatility"]["pstree"]:
                    res_file = self.volatility_plugin(
                        plugin_name="windows.pstree", logger=self.logger
                    )
                    self.volatility_send_results(
                        result_file=res_file, logger=self.logger
                    )
                self.update_workflow_status(
                    plugin="volatility", module="pstree", status=Status.FINISHED
                )
            except Exception as ex:
                self.error(f"[volatility ERROR] {str(ex)}")
                self.update_workflow_status(
                    plugin="volatility", module="pstree", status=Status.ERROR
                )
            try:
                self.update_workflow_status(
                    plugin="volatility", module="netscan", status=Status.STARTED
                )
                if self.config["run"]["volatility"]["netscan"]:
                    res_file = self.volatility_plugin(
                        plugin_name="windows.netscan", logger=self.logger
                    )
                    self.volatility_send_results(
                        result_file=res_file, logger=self.logger
                    )
                self.update_workflow_status(
                    plugin="volatility", module="netscan", status=Status.FINISHED
                )
            except Exception as ex:
                self.error(f"[volatility ERROR] {str(ex)}")
                self.update_workflow_status(
                    plugin="volatility", module="netscan", status=Status.ERROR
                )
            try:
                self.update_workflow_status(
                    plugin="volatility", module="netstat", status=Status.STARTED
                )
                if self.config["run"]["volatility"]["netstat"]:
                    res_file = self.volatility_plugin(
                        plugin_name="windows.netstat", logger=self.logger
                    )
                    self.volatility_send_results(
                        result_file=res_file, logger=self.logger
                    )
                self.update_workflow_status(
                    plugin="volatility", module="netstat", status=Status.FINISHED
                )
            except Exception as ex:
                self.error(f"[volatility ERROR] {str(ex)}")
                self.update_workflow_status(
                    plugin="volatility", module="netstat", status=Status.ERROR
                )
            self.update_workflow_status(
                plugin="volatility", module="plugin", status=Status.FINISHED
            )
        except Exception as ex:
            self.error(f"[volatility] run {str(ex)}")
            self.update_workflow_status(
                plugin="volatility", module="plugin", status=Status.ERROR
            )
            raise ex
