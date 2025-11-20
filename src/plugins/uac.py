import os
from logging import Logger
from src.thirdparty import triageutils as triageutils
from src.thirdparty.wrapper_docker import WrapperDocker
from src import BasePlugin, Status
import yaml
from datetime import datetime, timezone
from pathlib import Path


class Plugin(BasePlugin):
    """
    UAC plugin pour triage
    """

    def __init__(self, conf: dict):
        super().__init__(config=conf)
        self.tar_file = Path(os.path.join(self.upload_dir, conf["archive"]["name"]))
        self._docker = WrapperDocker(logger=self.logger)

        self.uac_dir = Path(os.path.join(self.upload_dir, self.hostname, "uac"))
        triageutils.create_directory_path(path=self.uac_dir, logger=self.logger)

        self.tar_destination = Path(os.path.join(self.uac_dir, "extract"))
        triageutils.create_directory_path(path=self.tar_destination, logger=self.logger)
        self.config["general"]["extracted_zip"] = f"{self.tar_destination}"
        self.update_config_file(data=self.config)

        self.plaso_dir = Path(os.path.join(self.uac_dir, "plaso"))
        triageutils.create_directory_path(path=self.plaso_dir, logger=self.logger)

        self.filebeat_dir = Path(os.path.join(self.uac_dir, "filebeat"))
        triageutils.create_directory_path(path=self.filebeat_dir, logger=self.logger)
        self.log_dirs = (
            dict()
        )  # for filebeat volumes: ex {apache: "/home/user/.../elk/apache"}

    @triageutils.LOG
    def extract_archive(
        self, archive: Path, dest: Path, specific_files: list = [], logger=None
    ):
        """Extrait tous les fichiers de l'archive TAR contenant les résultats uac.

        Args:
            archive (str): optionnel chemin complet du fichier tar
            dest (str): optionnel chemin complet de décompression de l'archive
            specific_files (tab): optionnel tableau avec le nom de fichier spécifiques à extraire
        """
        try:
            triageutils.extract_tar_archive(
                archive=archive,
                dest=dest,
                specific_files=specific_files,
                logger=self.logger,
            )
            mv_sfile = os.path.join(dest, "[root]")
            mv_dfile = os.path.join(dest, "root")
            if not triageutils.directory_exists(dir=mv_dfile, logger=self.logger):
                triageutils.move_file(src=mv_sfile, dst=mv_dfile, logger=self.logger)
        except Exception as ex:
            raise ex

    @triageutils.LOG
    def uac_generate_timeline(self, logger=None) -> Path:
        """Génère le PLASO et l'envoie à timesketch
        Args:

        Returns:
            plaso file path (Path)
        """
        try:
            cmd = [
                "log2timeline.py",
                "-z",
                "UTC",
                "--storage_file",
                f"{self.tar_destination}/{self.hostname}.plaso",
                self.tar_file.as_posix(),
            ]
            self._docker.image = f'{self.docker_images["plaso"]["image"]}:{self.docker_images["plaso"]["tag"]}'
            if not self._docker.is_image_present(name=self._docker.image):
                raise Exception("Image not present")
            self._docker.container = f"{self.uuid}-uac"
            self._docker.volumes = [f"{self.data_volume}:/data"]
            self._docker.execute_cmd(cmd=cmd)
            triageutils.move_file(
                src=self.tar_destination / f"{self.hostname}.plaso",
                dst=self.plaso_dir / f"{self.hostname}.plaso",
                logger=self.logger,
            )
            s_file = self.plaso_dir / f"{self.hostname}.plaso"
            if self.is_timesketch_active:
                triageutils.import_timesketch(
                    timelinename=f"{self.hostname}_UAC_DISK",
                    file=s_file,
                    timesketch_id=self.timesketch_id,
                    logger=self.logger,
                )
            return s_file
        except Exception as ex:
            raise ex

    @triageutils.LOG
    def uac_psort_timeline(self, plasofile: Path, logger: Logger) -> Path:
        """Génère la timeline avec PSORT du fichier plaso.
        Args:
            plasofile (Path): Plaso file path

        Returns:
            (Path) PSORT file path

        """
        try:
            cmd = [
                "psort.py",
                "-o",
                "json_line",
                "-a",
                "-w",
                f"{self.plaso_dir}/psort-{self.hostname}.jsonl",
                plasofile.as_posix(),
            ]
            self._docker.image = f'{self.docker_images["plaso"]["image"]}:{self.docker_images["plaso"]["tag"]}'
            if not self._docker.is_image_present(name=self._docker.image):
                raise Exception("Image not present")
            self._docker.container = f"{self.uuid}-psort"
            self._docker.volumes = [f"{self.data_volume}:/data"]
            self._docker.execute_cmd(cmd=cmd)

            s_file = self.plaso_dir / f"psort-{self.hostname}.jsonl"
            return s_file
        except Exception as ex:
            raise ex

    @triageutils.LOG
    def uac_get_logs(self, logger=None):
        try:
            for folder in self.uac_artifacts:
                self.info(f"Folder: {folder}")
                for pattern in self.uac_artifacts[folder]:
                    self.info(f"Pattern: {pattern}")
                    SearchedPath = pattern.rsplit("/", 1)[0]
                    SearchedFilename = pattern.rsplit("/", 1)[-1]
                    if SearchedPath.startswith("/"):
                        SearchedPath = SearchedPath[1:]
                    all_logs = triageutils.search_files(
                        src=os.path.join(self.uac_dir, self.tar_destination, "root"),
                        patterninpath=SearchedPath,
                        pattern=SearchedFilename.replace("*", ""),
                        logger=self.logger,
                    )
                    self.info(f"Files Found: {len(all_logs)}")
                    if len(all_logs):
                        log_dir = os.path.join(self.filebeat_dir, folder)
                        triageutils.create_directory_path(
                            path=log_dir, logger=self.logger
                        )
                        self.log_dirs[folder] = log_dir
                        triageutils.copy_files(
                            src=all_logs, dst=log_dir, logger=self.logger
                        )
            for k, v in self.log_dirs.items():
                # search zip or tar files
                files = triageutils.search_files(src=v, pattern="", logger=self.logger)
                try:
                    for filename in files:
                        if filename.endswith(".zip"):
                            extract_dir = filename.rsplit("/", 1)[-1].split(".zip")[0]
                            extract_path = os.path.join(v, extract_dir)
                            self.info(f"[uac_get_logs] ZIP archive => {filename}")
                            triageutils.create_directory_path(
                                path=extract_path, logger=self.logger
                            )
                            triageutils.extract_zip_archive(
                                archive=filename, dest=extract_path, logger=self.logger
                            )
                        elif filename.endswith(".tar"):
                            extract_dir = filename.rsplit("/", 1)[-1].split(".tar")[0]
                            extract_path = os.path.join(v, extract_dir)
                            self.info(f"[uac_get_logs] TAR archive => {filename}")
                            triageutils.create_directory_path(
                                path=extract_path, logger=self.logger
                            )
                            triageutils.extract_tar_archive(
                                archive=filename, dest=extract_path, logger=self.logger
                            )
                        elif filename.endswith(".tar.gz"):
                            extract_dir = filename.rsplit("/", 1)[-1].split(".tar.gz")[
                                0
                            ]
                            extract_path = os.path.join(v, extract_dir)
                            self.info(f"[uac_get_logs] TAR archive => {filename}")
                            triageutils.create_directory_path(
                                path=extract_path, logger=self.logger
                            )
                            triageutils.extract_tar_archive(
                                archive=filename, dest=extract_path, logger=self.logger
                            )
                        elif filename.endswith(".gz"):
                            extract_dir = filename.rsplit("/", 1)[-1].split(".gz")[0]
                            extract_path = os.path.join(v, f"{extract_dir}.log")
                            self.info(f"[uac_get_logs] GZIP archive => {filename}")
                            triageutils.extract_gzip_archive(
                                archive=filename, dest=extract_path, logger=self.logger
                            )
                except Exception as e:
                    self.error(f"[uac_get_logs] extract error - {e}")
        except Exception as ex:
            self.error(f"[uac_get_logs] {str(ex)}")

    @triageutils.LOG
    def ymlcreator(self, logger=None) -> Path:
        try:
            ip = self.logstash_url
            if ip.startswith("http"):
                ip = self.logstash_url.split("//")[1]
            _data = triageutils.generate_filebeat_config(
                ip=ip,
                port=self.filebeat_port,
                client=self.clientname,
                hostname=self.hostname,
                logger=self.logger,
            )
            new_config = self.filebeat_dir / Path("filebeat.docker.yml")
            with open(new_config.as_posix(), "w") as file:
                yaml.dump(_data, file, sort_keys=False)
            return new_config
        except Exception as ex:
            raise ex

    @triageutils.LOG
    def uac_filebeat(self, filebeat_config: Path, logger=None):
        """
        Fonction permettant de créer et de gérer filebeat et les fichiers de logs Linux

        Returns:
        """
        try:
            voldisk = [
                f"{self.data_volume}:/data",
                f"{filebeat_config}:/usr/share/filebeat/filebeat.yml:ro",
            ]
            for k, v in self.log_dirs.items():
                voldisk.append(f"{v}:/tmp/{k}")
            if not triageutils.file_exists(file=filebeat_config, logger=self.logger):
                raise Exception("Filebeat yaml not present")
            cmd = ["filebeat", "-e", "--once", "--strict.perms=false"]
            self._docker.image = f'{self.docker_images["filebeat"]["image"]}:{self.docker_images["filebeat"]["tag"]}'
            if not self._docker.is_image_present(name=self._docker.image):
                raise Exception("Image not present")
            self._docker.container = f"{self.uuid}-filebeat"
            self._docker.volumes = voldisk
            self._docker.execute_cmd(cmd=cmd)
        except Exception as ex:
            self.error(f"[uac_filebeat ERROR] {str(ex)}")
            raise ex

    @triageutils.LOG
    def run(self, logger=None):
        """Fonction principale qui exécute tout le triage de uac

        Args:

        Returns:

        """
        try:
            _exceptions = list()
            self.update_workflow_status(
                plugin="uac", module="plugin", status=Status.STARTED
            )
            self.extract_archive(
                archive=self.tar_file, dest=self.tar_destination, logger=self.logger
            )
            if self.config["run"]["uac"]["filebeat"]:
                try:
                    if self.is_logstash_active:
                        self.update_workflow_status(
                            plugin="uac", module="filebeat", status=Status.STARTED
                        )
                        self.uac_get_logs(logger=self.logger)
                        _filebeat_config = self.ymlcreator(logger=self.logger)
                        self.uac_filebeat(
                            filebeat_config=_filebeat_config, logger=self.logger
                        )
                        self.update_workflow_status(
                            plugin="uac", module="filebeat", status=Status.FINISHED
                        )
                    else:
                        raise Exception("logstash is not active")
                except Exception as ex:
                    self.error(f"[Filebeat ERROR] {ex}")
                    _exceptions.append(str(ex))
                    self.update_workflow_status(
                        plugin="uac", module="filebeat", status=Status.ERROR
                    )
            if self.config["run"]["uac"]["plaso"]:
                try:
                    self.update_workflow_status(
                        plugin="uac", module="plaso", status=Status.STARTED
                    )
                    _plaso_file = self.uac_generate_timeline(logger=self.logger)
                    self.uac_psort_timeline(plasofile=_plaso_file, logger=self.logger)
                    self.update_workflow_status(
                        plugin="uac", module="plaso", status=Status.FINISHED
                    )
                except Exception as ex:
                    self.error(f"[Plaso ERROR] {ex}")
                    _exceptions.append(str(ex))
                    self.update_workflow_status(
                        plugin="uac", module="plaso", status=Status.ERROR
                    )
            if len(_exceptions) > 0:
                raise Exception(str(_exceptions))
            self.update_workflow_status(
                plugin="uac", module="plugin", status=Status.FINISHED
            )
        except Exception as ex:
            self.error(f"[UAC] run {str(ex)}")
            self.update_workflow_status(
                plugin="uac", module="plugin", status=Status.ERROR
            )
            raise ex
        finally:
            self._docker.kill_containers_by_name(name=self.uuid)
            self.info("[UAC] End processing")
