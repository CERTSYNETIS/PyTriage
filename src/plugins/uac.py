import os
import docker
from src.thirdparty import triageutils as triageutils
from src import BasePlugin
import yaml


class Plugin(BasePlugin):
    """
    UAC plugin pour triage
    """

    def __init__(self, conf: dict):
        super().__init__(config=conf)
        self.tar_file = os.path.join(self.upload_dir, conf["archive"]["name"])
        self.uac_dir = os.path.join(self.upload_dir, self.hostname, "uac")
        triageutils.create_directory_path(path=self.uac_dir, logger=self.logger)
        self.tar_destination = os.path.join(self.uac_dir, "extract")
        triageutils.create_directory_path(path=self.tar_destination, logger=self.logger)
        self.config["general"]["extracted_zip"] = f"{self.tar_destination}"
        _updt = triageutils.update_config_file(
            data=self.config,
            conf_file=f'{self.config["general"]["extract"]}/config.yaml',
            logger=self.logger,
        )

        self.plaso_dir = os.path.join(self.uac_dir, "plaso")
        triageutils.create_directory_path(path=self.plaso_dir, logger=self.logger)
        self.filebeat_dir = os.path.join(self.uac_dir, "filebeat")
        triageutils.create_directory_path(path=self.filebeat_dir, logger=self.logger)
        self.log_dirs = (
            dict()
        )  # for filebeat volumes: ex {apache: "/home/user/.../elk/apache"}

    @triageutils.LOG
    def extract_archive(self, archive=None, dest=None, specific_files=[], logger=None):
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
            self.logger.error(f"[UAC] {ex}")
            raise ex

    @triageutils.LOG
    def check_docker_image(
        self,
        image_name: str,
        tag: str,
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
    def uac_generate_timeline(self, logger=None):
        """Génère la timeline de BODYFILE.TXT et l'envoie à timesketch
        Args:

        Returns:

        """
        try:
            if not self.config["run"]["uac"]["timeline"]:
                self.info("[uac_generate_timeline] Run Plaso: False")
                return
            _docker = docker.from_env()
            t_file = os.path.join(self.tar_destination, "bodyfile", "bodyfile.txt")

            if not triageutils.file_exists(file=t_file, logger=self.logger):
                self.error("cannot generate uac timeline file not present")
                return
            self.info("Start DOCKER log2timeline")

            cmd = [
                "log2timeline.py",
                "-z",
                "UTC",
                "--storage_file",
                f"{self.tar_destination}/{self.hostname}.plaso",
                self.tar_file,
            ]
            # https://docs.docker.com/engine/api/v1.42/
            container = _docker.containers.run(
                image=f'{self.docker_images["plaso"]["image"]}:{self.docker_images["plaso"]["tag"]}',
                auto_remove=True,
                detach=True,
                command=cmd,
                volumes=[f"{self.data_volume}:/data"],
                stderr=True,
                stdout=True,
                name=f"{self.clientname}-{self.hostname}-PLASO-UAC",
            )
            container.wait()
            triageutils.move_file(
                src=os.path.join(self.tar_destination, f"{self.hostname}.plaso"),
                dst=os.path.join(self.plaso_dir, f"{self.hostname}.plaso"),
                logger=self.logger,
            )
            self.info("END DOCKER log2timeline")
            s_file = os.path.join(self.plaso_dir, f"{self.hostname}.plaso")
            if self.is_timesketch_active:
                triageutils.import_timesketch(
                    timelinename=f"{self.hostname}_UAC_DISK",
                    file=s_file,
                    timesketch_id=self.timesketch_id,
                    logger=self.logger,
                )
        except Exception as ex:
            self.error(f"[uac_generate_timeline] {str(ex)}")

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
    def ymlcreator(self, logger=None):
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
            new_config = os.path.join(self.filebeat_dir, "filebeat.docker.yml")
            with open(new_config, "w") as file:
                yaml.dump(_data, file, sort_keys=False)
        except Exception as ex:
            self.error(f"[UAC] ymlcreator - {str(ex)}")
            raise ex

    @triageutils.LOG
    def uac_filebeat(self, logger=None):
        """
        Fonction permettant de créer et de gérer filebeat et les fichiers de logs Linux

        Returns:
        """
        # client = docker.from_env()
        try:
            if not self.config["run"]["uac"]["filebeat"]:
                self.info("[uac_filebeat] Run Filebeat: False")
                return
            elk_file = os.path.join(self.filebeat_dir, "filebeat.docker.yml")
            voldisk = [
                f"{self.data_volume}:/data",
                f"{elk_file}:/usr/share/filebeat/filebeat.yml:ro",
            ]
            for k, v in self.log_dirs.items():
                voldisk.append(f"{v}:/tmp/{k}")
            self.info(f"VolDirs: {voldisk}")

            if not triageutils.file_exists(file=elk_file, logger=self.logger):
                self.error("[uac_filebeat] cannot generate filebeat yaml not present")
                # raise Exception("[uac_filebeat] cannot generate filebeat yaml not present")
                return
            self.info("Start DOCKER FileBeat")
            _docker = docker.from_env()
            cmd = ["filebeat", "-e", "--once", "--strict.perms=false"]
            container = _docker.containers.run(
                image=f'{self.docker_images["filebeat"]["image"]}:{self.docker_images["filebeat"]["tag"]}',
                auto_remove=True,
                detach=True,
                command=cmd,
                volumes=voldisk,
                network_mode="host",
                stderr=True,
                stdout=True,
                name=f"{self.clientname}-{self.hostname}-FILEBEAT-UAC",
            )
            container.wait()
            self.info("END DOCKER FileBeat")

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
            self.extract_archive(
                archive=self.tar_file, dest=self.tar_destination, logger=self.logger
            )

            if self.config["run"]["uac"]["filebeat"] and self.is_logstash_active:
                self.uac_get_logs(logger=self.logger)
                self.ymlcreator(logger=self.logger)
                self.check_docker_image(
                    image_name=self.docker_images["filebeat"]["image"],
                    tag=self.docker_images["filebeat"]["tag"],
                    logger=self.logger,
                )
                self.uac_filebeat(logger=self.logger)
            if self.config["run"]["uac"]["timeline"]:
                self.check_docker_image(
                    image_name=self.docker_images["plaso"]["image"],
                    tag=self.docker_images["plaso"]["tag"],
                    logger=self.logger,
                )
                self.uac_generate_timeline(logger=self.logger)
        except Exception as ex:
            self.error(f"[UAC] run {str(ex)}")
            self.info("Exception so kill my running containers")
            self.kill_docker_container(logger=self.logger)
            raise ex
