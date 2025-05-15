import os
import docker
import yaml
import time
from src.thirdparty import triageutils as triageutils
from src.thirdparty.AESCipher import AESCipher
from src.thirdparty.ParseEVTX import ParseEVTX
from src.thirdparty.ParseRegistry import ParseRegistry
from src.thirdparty.ParseUSNJRNL import ParseUSNJRNL
from src.thirdparty.ParsePrefetch import ParsePrefetch
from src.thirdparty.ParseMFT.mft_analyzer import MftAnalyzer
from src.thirdparty.ParseMPLog import ParseMPLog
from src.thirdparty.winactivities.ParseWinactivities import ParseWinActivities
from src.thirdparty.trashparse.ParseTrash import TrashParse
from logging import Logger
from src import BasePlugin
import typing as t
from json import loads
from pathlib import Path
from zipfile import ZipFile
from pyzipper import AESZipFile
from base64 import b64decode
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
)
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from datetime import datetime, timezone


class Plugin(BasePlugin):
    """
    GENERAPTOR plugin pour triage du ZIP
    """

    def __init__(self, conf: dict):
        super().__init__(config=conf)
        self.zipfile = Path(os.path.join(self.upload_dir, conf["archive"]["name"]))

        self.private_key_file = Path(
            os.path.join(self.upload_dir, conf["run"]["generaptor"]["private_key_file"])
        )
        _AESprivkey = AESCipher(key=conf["uuid"])
        self.private_key_secret = _AESprivkey.decrypt(
            enc=bytes(conf["run"]["generaptor"]["private_key_secret"], "utf-8")
        )
        self.generaptor_dir = Path(
            os.path.join(self.upload_dir, self.hostname, "generaptor")
        )
        triageutils.create_directory_path(path=self.generaptor_dir, logger=self.logger)

        self.zip_destination = Path(os.path.join(self.generaptor_dir, "extract"))
        triageutils.create_directory_path(path=self.zip_destination, logger=self.logger)
        self.config["general"]["extracted_zip"] = f"{self.zip_destination}"
        _updt = triageutils.update_config_file(
            data=self.config,
            conf_file=f'{self.config["general"]["extract"]}/config.yaml',
            logger=self.logger,
        )

        self.evtx_share = Path(os.path.join(self.generaptor_dir, "EVTX_Orig"))
        triageutils.create_directory_path(path=self.evtx_share, logger=self.logger)

        self.evtx_parsed_share = Path(os.path.join(self.generaptor_dir, "EVTX_Parsed"))
        triageutils.create_directory_path(
            path=self.evtx_parsed_share, logger=self.logger
        )

        self.ntfs_share = Path(os.path.join(self.generaptor_dir, "NTFS"))
        triageutils.create_directory_path(path=self.ntfs_share, logger=self.logger)

        self.reg_share = Path(os.path.join(self.generaptor_dir, "REGISTRY"))
        triageutils.create_directory_path(path=self.reg_share, logger=self.logger)

        self.mplog_share = Path(os.path.join(self.generaptor_dir, "MPLog"))
        triageutils.create_directory_path(path=self.mplog_share, logger=self.logger)

        self.prefetch_share = Path(os.path.join(self.generaptor_dir, "Prefetch"))
        triageutils.create_directory_path(path=self.prefetch_share, logger=self.logger)

        self.iis_share = Path(os.path.join(self.generaptor_dir, "iis"))
        triageutils.create_directory_path(path=self.iis_share, logger=self.logger)

        self.plaso_folder = os.path.join(self.generaptor_dir, "plaso")
        triageutils.create_directory_path(path=self.plaso_folder, logger=self.logger)

        self.filebeat_dir = os.path.join(self.generaptor_dir, "filebeat")
        triageutils.create_directory_path(path=self.filebeat_dir, logger=self.logger)

        self.activitiescache_share = os.path.join(
            self.generaptor_dir, "ActivitiesCache"
        )
        triageutils.create_directory_path(
            path=self.activitiescache_share, logger=self.logger
        )

        self.recyclebin_dir = Path(os.path.join(self.generaptor_dir, "RecycleBin"))
        triageutils.create_directory_path(path=self.recyclebin_dir, logger=self.logger)

        self.psreadline_dir = Path(os.path.join(self.generaptor_dir, "PSReadLine"))
        triageutils.create_directory_path(path=self.psreadline_dir, logger=self.logger)

        self.log_dirs = (
            dict()
        )  # for filebeat volumes: ex {apache: "/home/user/.../elk/apache"}
        self._data_filename = "data.zip"

    @property
    def metadata(self) -> t.Mapping[str, str]:
        """Collection metadata"""
        if not hasattr(self, "__metadata"):
            with ZipFile(self.zipfile) as zipf:
                zipinf = zipf.getinfo("metadata.json")
                data = zipf.read(zipinf)
                (__metadata,) = loads(data.decode())
            setattr(self, "__metadata", __metadata)
        return getattr(self, "__metadata")

    @property
    def device(self) -> t.Optional[str]:
        """Retrieve hostname in metadata"""
        return self.metadata.get("device")

    @property
    def fingerprint(self) -> t.Optional[str]:
        """Retrieve public key fingerprint in metadata"""
        return self.metadata.get("fingerprint_hex")

    @triageutils.LOG
    def extract_to(self, directory: Path, secret: str, logger: Logger = None) -> bool:
        """Extract collection archive data to directory"""
        # extract and decrypt data.zip archive
        self.info(f"extracting and decrypting {self._data_filename}")
        try:
            with AESZipFile(
                self.zipfile,
                "r",
            ) as zipf:
                zipf.setpassword(secret.encode("utf-8"))
                zipf.extract(self._data_filename, path=str(directory))
        except RuntimeError:
            self.error("encrypted archive extraction failed!")
            return False
        # extract data.zip content
        self.info(f"extracting {self._data_filename} content")
        success = True
        data_filepath = directory / self._data_filename
        try:
            with ZipFile(data_filepath, "r") as zipf:
                zipf.extractall(path=directory)
        except Exception as ex:
            success = False
            self.error(f"data archive extraction failed: {ex}")
        finally:
            data_filepath.unlink()
        return success

    @triageutils.LOG
    def _check_same_fingerprint(self, private_key: Path, logger: Logger = None):
        if not private_key.name.startswith(self.fingerprint):
            self.error("given key does not match given collections fingerprint")
            self.error(f"expected: {self.fingerprint}")
            return False
        return True

    @triageutils.LOG
    def load_private_key(
        self,
        private_key_path: Path,
        private_key_secret: t.Optional[str] = None,
        logger: Logger = None,
    ) -> t.Optional[RSAPrivateKey]:
        """Load PEM encoded encrypted private key from file"""
        if not private_key_secret:
            self.error("failed to provide private key secret")
            return None
        return load_pem_private_key(
            private_key_path.read_bytes(), private_key_secret.encode()
        )

    @triageutils.LOG
    def decrypt_secret(
        self, private_key: RSAPrivateKey, b64_enc_secret: str, logger: Logger = None
    ) -> bytes:
        """Decrypt a base64-encoded secret using given private key"""
        enc_secret = b64decode(b64_enc_secret)
        secret = private_key.decrypt(
            enc_secret,
            OAEP(mgf=MGF1(algorithm=SHA512()), algorithm=SHA512(), label=None),
        )
        return secret

    @triageutils.LOG
    def _secret(
        self, private_key: RSAPrivateKey, logger: Logger = None
    ) -> t.Optional[str]:
        """Retrieve collection secret"""
        b64_enc_secret = self.metadata.get("b64_enc_secret")
        if not b64_enc_secret:
            return None
        secret_bytes = self.decrypt_secret(private_key, b64_enc_secret)
        return secret_bytes.decode()

    @triageutils.LOG
    def _extract_cmd(
        self,
        archive: Path,
        private_key: Path,
        output_directory: Path,
        private_key_secret: str,
        logger: Logger = None,
    ):
        if not self._check_same_fingerprint(
            private_key=private_key, logger=self.logger
        ):
            return
        try:
            private_key = self.load_private_key(private_key, private_key_secret)
        except ValueError as ex:
            self.error("invalid private key and/or passphrase")
            self.error(ex)
            return
        try:
            secret = self._secret(private_key)
        except ValueError:
            self.error("private key does not match collection archive")
            return
        dirname = self.hostname  # f"{archive.stem}"
        directory = output_directory / dirname
        directory.mkdir(parents=True, exist_ok=True)
        self.info(f"extracting: {archive}")
        self.info(f"        to: {directory}")
        self.extract_to(directory=directory, secret=secret)

    @triageutils.LOG
    def check_docker_image(
        self,
        image_name="dockerhub.cert.lan/log2timeline/plaso",
        tag="20230717",
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
    def kill_docker_container(self, logger: Logger):
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
    def generate_plaso_timeline(self, logger: Logger):
        """Génère la timeline de PLASO.
        Args:

        Returns:

        """
        try:
            _docker = docker.from_env()
            if triageutils.file_exists(
                file=f"{self.zip_destination}/{self.hostname}.plaso",
            ):
                triageutils.delete_file(
                    src=f"{self.zip_destination}/{self.hostname}.plaso",
                )
            self.info(f"Docker volume to mount: {self.data_volume}")
            self.info("Start Docker log2timeline/plaso all parsers")
            cmd = [
                "log2timeline.py",
                "--storage_file",
                f"{self.zip_destination}/{self.hostname}.plaso",
                f"{self.zip_destination}/{self.hostname}/uploads",
            ]
            container = _docker.containers.run(
                image=f'{self.docker_images["plaso"]["image"]}:{self.docker_images["plaso"]["tag"]}',
                auto_remove=True,
                detach=True,
                command=cmd,
                volumes=[f"{self.data_volume}:/data"],
                stderr=True,
                stdout=True,
                name=f"{self.clientname}-{self.hostname}-DISK",
            )
            container.wait()
            self.info("STOP Docker log2timeline/plaso")
            s_file = os.path.join(self.plaso_folder, f"{self.hostname}.plaso")
            triageutils.move_file(
                src=os.path.join(self.zip_destination, f"{self.hostname}.plaso"),
                dst=s_file,
                logger=self.logger,
            )
            if self.is_timesketch_active:
                triageutils.import_timesketch(
                    timelinename=f"{self.hostname}_DISK",
                    file=s_file,
                    timesketch_id=self.timesketch_id,
                    logger=self.logger,
                )
        except Exception as ex:
            self.logger.error(f"[generate_plaso_timeline] {ex}")

    @triageutils.LOG
    def generate_psort_timeline(self, plasofile: str, logger: Logger) -> str:
        """Génère la timeline avec PSORT du fichier plaso en entrée et l'envoie à ELK.
        Args:
            plasofile (str): chemin du fichier plaso à parser

        Returns:
            (str) file path généré

        """
        try:
            if not plasofile:
                raise Exception("No PLASO file given")
            self.info(f"Start Docker PLASO/psort on {plasofile}")
            _slice = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
            _slice_size = 1051200

            cmd = [
                "psort.py",
                "-o",
                "json_line",
                "--slice",
                f"{_slice}",
                "--slice_size",
                f"{_slice_size}",
                "-a",
                "-w",
                f"{self.plaso_folder}/psort-{self.hostname}.jsonl",
                f"{self.plaso_folder}/{plasofile}",
            ]

            _docker = docker.from_env()
            container = _docker.containers.run(
                image=f'{self.docker_images["plaso"]["image"]}:{self.docker_images["plaso"]["tag"]}',
                auto_remove=True,
                detach=True,
                command=cmd,
                volumes=[f"{self.data_volume}:/data"],
                stderr=True,
                stdout=True,
                name=f"{self.clientname}-{self.hostname}-psort",
            )
            container.wait()
            self.info(f"STOP Docker PLASO/psort on {plasofile}")
            s_file = os.path.join(self.plaso_folder, f"psort-{self.hostname}.jsonl")
            return s_file
        except Exception as ex:
            self.logger.error(f"[generate_psort_timeline] {ex}")
            return ""

    @triageutils.LOG
    def send_psort_to_elk(self, psortfile: str, logger: Logger) -> None:
        """Fonction qui envoie les résultats psort vers ELK"""
        try:
            if not psortfile:
                raise Exception("No PSORT file given")
            extrafields = dict()
            extrafields["csirt"] = dict()
            extrafields["csirt"]["client"] = self.clientname
            extrafields["csirt"]["hostname"] = self.hostname
            extrafields["csirt"]["application"] = "psort"
            ip = self.logstash_url
            if ip.startswith("http"):
                ip = self.logstash_url.split("//")[1]
            triageutils.send_jsonl_to_elk(
                filepath=psortfile,
                ip=ip,
                port=self.psort_port,
                extrafields=extrafields,
                logger=self.logger,
            )
        except Exception as e:
            self.error(f"[send_psort_to_elk] {str(e)}")
            raise e

    @triageutils.LOG
    def get_evtx(self, evtx_folder: Path, logger: Logger) -> list:
        """Copie les fichiers evtx présents dans le dossier vers le dossier partagé.
        Args:
            evtx_folder (str): optionnel chemin du dossier contenant les fichiers evtx si pas de dossier, il cherche dans tout le vhdx
        Returns:
            un tableau contenant le nom de tous les fichiers trouvés
        """
        records = []
        if not evtx_folder:
            raise Exception("No evtx folder")
        records.extend(
            triageutils.search_files(
                src=evtx_folder, pattern=".evtx", logger=self.logger
            )
        )
        if len(records):
            triageutils.copy_files(
                src=records, dst=self.evtx_share, overwrite=True, logger=self.logger
            )
        return records

    @triageutils.LOG
    def send_logs_to_winlogbeat(self, evtx_logs: list, logger: Logger) -> bool:
        """Copie les evtx vers le dossier partagé sur la VM Winlogbeat.
        Args:
            evtx_logs (list): Liste contenant les chemins des fichiers de log
        Returns:
            result (bool): True or False
        """
        result = True
        self.info(f"[send_logs_to_winlogbeat] Total EVTX: {len(evtx_logs)}")
        if not len(evtx_logs):
            self.error("[send_logs_to_winlogbeat] No EVTX logs to send")
            return False
        try:
            win_log_path = os.path.join(self.winlogbeat, self.clientname, self.hostname)
            if triageutils.create_directory_path(path=win_log_path, logger=self.logger):
                self.info(
                    f"[send_logs_to_winlogbeat] WinLogBeat created: {win_log_path}"
                )
                result &= triageutils.copy_files(
                    src=evtx_logs, dst=win_log_path, overwrite=True, logger=self.logger
                )
        except Exception as ex:
            self.error(f"[send_logs_to_winlogbeat] {ex}")
        self.info(f"[send_logs_to_winlogbeat] result: {result}")
        return result

    @triageutils.LOG
    def get_iis_logs(self, logger: Logger) -> list:
        """Copie les fichiers de logs du serveur IIS présents dans le dossier vers le dossier partagé.
        Args:
            iis_folder (str): optionnel chemin du dossier
        Returns:
            un tableau contenant le nom de tous les fichiers trouvés
        """
        records = []
        pattern = ".log"

        iis_folder = triageutils.get_folder_path_by_name(
            folder_name="inetpub", root=self.zip_destination
        )

        if iis_folder:
            triageutils.copy_directory(
                src=iis_folder, dst=self.iis_share, logger=self.logger
            )
            records.extend(
                triageutils.search_files_by_extension(
                    dir=self.iis_share, extension=pattern, logger=self.logger
                )
            )
        return records

    @triageutils.LOG
    def send_iis_logs(self, iis_logs: list, logger: Logger) -> bool:
        """Parse les fichiers de log IIS puis les envoies vers ELK.
        Args:
            iis_logs (list): Liste contenant les chemins des fichiers de log
        Returns:

        """
        if not len(iis_logs):
            self.error("[send_iis_logs] No IIS logs to send")
            return False
        count = 0
        total = len(iis_logs)
        ip = self.logstash_url
        if ip.startswith("http"):
            ip = self.logstash_url.split("//")[1]
        for file in iis_logs:
            try:  # For non blocking error
                if file.endswith(".log"):  # PROCESS only Log files
                    json_tab = []
                    with open(file, "r", errors="ignore") as log_to_parse:
                        count += 1
                        Lines = log_to_parse.readlines()
                        header_ok = False
                        header = []
                        for line in Lines:
                            if line.startswith("#Fields:") and not header_ok:
                                header_ok = True
                                header = line.split("#Fields: ")[1].split()
                            elif not line.startswith("#"):
                                fields = line.split()
                                data_to_send = dict(zip(header, fields))
                                # data_to_send["host_log_path"] = file
                                data_to_send["log"] = dict()
                                data_to_send["log"]["file"] = dict()
                                data_to_send["log"]["file"]["path"] = file
                                data_to_send["full_message"] = line
                                data_to_send["csirt"] = dict()
                                data_to_send["csirt"]["client"] = self.clientname
                                data_to_send["csirt"]["hostname"] = self.hostname
                                data_to_send["csirt"]["application"] = "iis"
                                json_tab.append(data_to_send)
                    self.info(f"[send_iis_logs] send file {count}/{total}")
                    triageutils.send_data_to_elk(
                        data=json_tab,
                        ip=ip,
                        port=self.iis_port,
                        logger=self.logger,
                    )
            except Exception as ex:
                self.error(f"[send_iis_logs] {ex} ")
        return True

    @triageutils.LOG
    def get_linux_logs(self, logger: Logger):
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
                        src=self.zip_destination,
                        patterninpath=SearchedPath,
                        pattern=SearchedFilename.replace("*", ""),
                        logger=logger,
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
                            self.info(f"[get_linux_logs] ZIP archive => {filename}")
                            triageutils.create_directory_path(
                                path=extract_path, logger=self.logger
                            )
                            triageutils.extract_zip_archive(
                                archive=filename, dest=extract_path, logger=self.logger
                            )
                        elif filename.endswith(".tar"):
                            extract_dir = filename.rsplit("/", 1)[-1].split(".tar")[0]
                            extract_path = os.path.join(v, extract_dir)
                            self.info(f"[get_linux_logs] TAR archive => {filename}")
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
                            self.info(f"[get_linux_logs] TAR archive => {filename}")
                            triageutils.create_directory_path(
                                path=extract_path, logger=self.logger
                            )
                            triageutils.extract_tar_archive(
                                archive=filename, dest=extract_path, logger=self.logger
                            )
                        elif filename.endswith(".gz"):
                            extract_dir = filename.rsplit("/", 1)[-1].split(".gz")[0]
                            extract_path = os.path.join(v, f"{extract_dir}.log")
                            self.info(f"[get_linux_logs] GZIP archive => {filename}")
                            triageutils.extract_gzip_archive(
                                archive=filename, dest=extract_path, logger=self.logger
                            )
                except Exception as e:
                    self.error(f"[get_linux_logs] extract error - {e}")
        except Exception as ex:
            self.error(f"[get_linux_logs] {str(ex)}")

    @triageutils.LOG
    def ymlcreator(self, logger: Logger):
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
            self.error(f"[generaptor] ymlcreator - {str(ex)}")
            raise ex

    @triageutils.LOG
    def generaptor_filebeat(self, logger: Logger):
        """
        Fonction permettant de créer et de gérer filebeat et les fichiers de logs Linux

        Returns:
        """
        try:
            elk_file = os.path.join(self.filebeat_dir, "filebeat.docker.yml")
            voldisk = [
                f"{elk_file}:/usr/share/filebeat/filebeat.yml:ro",
            ]
            for k, v in self.log_dirs.items():
                voldisk.append(f"{v}:/tmp/{k}")
            self.info(f"VolDirs: {voldisk}")

            if not triageutils.file_exists(file=elk_file, logger=self.logger):
                self.error(
                    "[generaptor_filebeat] cannot generate filebeat yaml not present"
                )
                return None
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
                name=f"{self.clientname}-{self.hostname}-FILEBEAT-GENERAPTOR",
            )
            container.wait()
            self.info("END DOCKER FileBeat")
        except Exception as ex:
            self.error(f"[generaptor_filebeat] {str(ex)}")
            raise ex

    @triageutils.LOG
    def generaptor_parse_evtx(self, logger: Logger):
        try:
            _ip = self.logstash_url
            if _ip.startswith("http"):
                _ip = self.logstash_url.split("//")[1]
            for _f in triageutils.search_files_generator(
                src=self.zip_destination, pattern=".evtx"
            ):
                triageutils.copy_file(
                    src=_f,
                    dst=self.evtx_share,
                    overwrite=True,
                    logger=self.logger,
                )
                _p = ParseEVTX(
                    evtxfilepath=_f,
                    ip=_ip,
                    port=self.evtxparser_port,
                    client=self.clientname,
                    hostname=self.hostname,
                    mapping=self.evtx_mapping,
                    output_folder=self.evtx_parsed_share,
                    logstash_is_active=self.is_logstash_active,
                    logger=self.logger,
                )
                _res = _p.parse_evtx()
                self.info(f"[generaptor_parse_evtx] {_res}")

                # send analytics info
                if self.is_logstash_active:
                    _file_infos = triageutils.get_file_informations(filepath=_f)
                    _analytics = triageutils.generate_analytics(logger=self.logger)
                    _analytics["log"]["file"]["eventcount"] = _res.get("nb_events_read", 0)
                    _analytics["log"]["file"]["eventsent"] = _res.get("nb_events_sent", 0)
                    _analytics["log"]["file"]["path"] = str(_f)
                    _analytics["log"]["file"]["size"] = _file_infos.get("fileSize", 0)
                    _analytics["log"]["file"]["lastaccessed"] = _file_infos.get("lastAccessTime", 0)
                    _analytics["log"]["file"]["creation"] = _file_infos.get("creationTime", 0)
                    _analytics["csirt"]["client"] = self.clientname
                    _analytics["csirt"]["hostname"] = self.hostname
                    _analytics["csirt"]["application"] = "generaptor_parse_evtx"
                    triageutils.send_data_to_elk(
                        data=_analytics,
                        ip=_ip,
                        port=self.selfassessment_port,
                        logger=self.logger,
                    )
        except Exception as ex:
            self.error(f"[generaptor_parse_evtx] {str(ex)}")
            raise ex

    @triageutils.LOG
    def generaptor_parse_registry(self, logger: Logger):
        try:
            _parse_reg = ParseRegistry(logger=self.logger)
            _parse_reg.parse_all(
                dir_to_reg=self.zip_destination, out_folder=self.reg_share
            )
        except Exception as ex:
            self.error(f"[generaptor_parse_registry] {str(ex)}")
            raise ex

    @triageutils.LOG
    def generaptor_parse_mft(self, logger: Logger):
        try:
            _mft_files = triageutils.search_files(
                src=self.zip_destination,
                pattern="$MFT",
                strict=True,
                logger=self.logger,
            )
            if len(_mft_files):
                _output_file = f"{self.ntfs_share}/mft_parsed.csv"
                _mft = _mft_files[0]
                _analyzer = MftAnalyzer(
                    mft_file=_mft, output_file=_output_file, logger=self.logger
                )
                _analyzer.analyze()
            else:
                self.logger.error(f"[generaptor_parse_mft] No $MFT found")
        except Exception as ex:
            self.error(f"[generaptor_parse_mft] {str(ex)}")
            raise ex

    @triageutils.LOG
    def generaptor_parse_usnjrnl(self, logger: Logger):
        try:
            _usn_files = triageutils.search_files(
                src=self.zip_destination, pattern="$UsnJrnl%3A$J", strict=True
            )
            if len(_usn_files):
                _csv_output_file = Path(f"{self.ntfs_share}/usn_parsed.csv")
                _body_output_file = Path(f"{self.ntfs_share}/usn_parsed.body")
                _usn = Path(_usn_files[0])
                _analyzer = ParseUSNJRNL(
                    usn_file=_usn,
                    result_csv_file=_csv_output_file,
                    result_body_file=_body_output_file,
                    logger=self.logger,
                )
                _analyzer.analyze()
            else:
                self.logger.error(f"[generaptor_parse_usnjrnl] No $UsnJrnl%3A$J found")
        except Exception as ex:
            self.error(f"[generaptor_parse_usnjrnl] {str(ex)}")
            raise ex

    @triageutils.LOG
    def generaptor_parse_prefetch(self, logger: Logger):
        try:
            for _f in triageutils.search_files_by_extension_generator(
                src=self.zip_destination,
                extension=".pf",
                patterninpath="prefetch",
                logger=self.logger,
            ):
                _output_file = Path(f"{self.prefetch_share}/{_f.parts[-1]}.json")
                _analyzer = ParsePrefetch(
                    prefetch=_f,
                    output=_output_file,
                    logger=self.logger,
                )
                _analyzer.analyze()
        except Exception as ex:
            self.error(f"[generaptor_parse_prefetch] {str(ex)}")
            raise ex

    @triageutils.LOG
    def generaptor_parse_mplog(self, logger: Logger):
        try:
            for _f in triageutils.search_files_generator(
                src=self.zip_destination,
                pattern="MPLog-",
                patterninpath="Windows Defender",
            ):
                self.info(f"[generaptor_parse_mplog] Parse: {_f}")
                _analyzer = ParseMPLog(mplog_file=_f, output_directory=self.mplog_share)
                _analyzer.orchestrator()
        except Exception as ex:
            self.error(f"[generaptor_parse_mplog] {str(ex)}")
            raise ex

    @triageutils.LOG
    def generaptor_parse_activitiescache(self, logger: Logger):
        try:
            for _f in triageutils.search_files_generator(
                src=self.zip_destination,
                pattern="ActivitiesCache.db",
                patterninpath="ConnectedDevicesPlatform",
                strict=True,
            ):
                self.info(f"[generaptor_parse_activitiescache] Parse: {_f}")
                _analyzer = ParseWinActivities(
                    DBfilepath=_f,
                    output_folder=self.activitiescache_share,
                    logger=self.logger,
                )
                _analyzer.process()
        except Exception as ex:
            self.error(f"[generaptor_parse_activitiescache] {str(ex)}")
            raise ex

    @triageutils.LOG
    def generaptor_parse_recyclebin(self, logger: Logger):
        try:
            _recyclebin_folder = triageutils.get_folder_path_by_name(
                folder_name="$Recycle.Bin",
                root=self.zip_destination,
                logger=self.logger,
            )
            if _recyclebin_folder:
                for _dir in triageutils.list_directory_full_path(
                    src=_recyclebin_folder,
                    onlydirs=True,
                    logger=self.logger,
                ):
                    _dir = Path(_dir)
                    self.info(f"[generaptor_parse_recyclebin] Parse: {_dir}")
                    trash = TrashParse(recyclebin_folder=_dir, logger=self.logger)
                    trash.listfile()
                    trash.parsefile()
                    _output = Path(self.recyclebin_dir / Path(f"{_dir.name}.csv"))
                    trash.write_csv(csv_file=_output)
                    _output = Path(self.recyclebin_dir / Path(f"{_dir.name}.jsonl"))
                    trash.write_jsonl(jsonl_file=_output)
            else:
                self.info("[generaptor_parse_recyclebin] No {$Recycle.Bin} Folder")
        except Exception as ex:
            self.error(f"[generaptor_parse_recyclebin] {ex}")

    @triageutils.LOG
    def generaptor_get_consolehost_history(self, logger: Logger):
        try:
            for _f in triageutils.search_files_generator(
                src=self.zip_destination,
                pattern="ConsoleHost_history.txt",
                patterninpath="PSReadLine",
                strict=True,
            ):
                self.info(f"[generaptor_get_consolehost_history] Parse: {_f}")
                try:
                    _username = _f.parts[_f.parts.index('Users')+1]
                except Exception as errorname:
                    self.error(f"{errorname}")
                    _username = time.time()
                _dst = self.psreadline_dir / Path(f"{_username}")
                triageutils.copy_file(src=_f, dst=_dst, overwrite=True, logger=self.logger)
        except Exception as ex:
            self.error(f"[generaptor_get_consolehost_history] {str(ex)}")
            raise ex


    @triageutils.LOG
    def run(self, logger: Logger):
        """Fonction principale qui exécute tout le triage de generaptor

        Args:

        Returns:

        """
        try:
            self._extract_cmd(
                archive=self.zipfile,
                private_key=self.private_key_file,
                output_directory=self.zip_destination,
                private_key_secret=self.private_key_secret,
                logger=self.logger,
            )
            if self.config["run"]["generaptor"]["linux"]:
                self.info("Linux Generaptor")
                self.get_linux_logs(logger=self.logger)
                if self.is_logstash_active:
                    self.ymlcreator(logger=self.logger)
                    self.check_docker_image(
                            image_name=self.docker_images["filebeat"]["image"],
                            tag=self.docker_images["filebeat"]["tag"],
                            logger=self.logger,
                        )
                    self.generaptor_filebeat(logger=self.logger)
                if self.config["run"]["generaptor"]["timeline"]:
                    self.info("[generaptor] Run PLASO")
                    self.check_docker_image(
                        image_name=self.docker_images["plaso"]["image"],
                        tag=self.docker_images["plaso"]["tag"],
                        logger=self.logger,
                    )
                    self.generate_plaso_timeline(logger=self.logger)
            else:
                self.info("Windows Generaptor")
                try:
                    triageutils.copy_directory(
                        src=os.path.join(
                            self.zip_destination, self.hostname, "results"
                        ),
                        dst=self.ntfs_share,
                    )
                except Exception as copy_err:
                    self.error(f"[RUN] {copy_err}")
                    pass
                if self.config["run"]["generaptor"].get("evtx", False):
                    self.info("[generaptor] Run EVTX")
                    if self.config["run"]["generaptor"]["winlogbeat"]:
                        evtx_logs = self.get_evtx(
                            evtx_folder=self.zip_destination, logger=self.logger
                        )
                        if self.is_winlogbeat_active:
                            self.send_logs_to_winlogbeat(
                                evtx_logs=evtx_logs, logger=self.logger
                            )
                    else:
                        self.generaptor_parse_evtx(logger=self.logger)
                if self.config["run"]["generaptor"].get("registry", False):
                    self.info("[generaptor] Run Registry")
                    try:
                        self.generaptor_parse_registry(logger=self.logger)
                    except Exception as err_reg:
                        self.error(f"[generaptor ERROR] {str(err_reg)}")
                if self.config["run"]["generaptor"].get("mft", False):
                    self.info("[generaptor] Run MFT")
                    try:
                        self.generaptor_parse_mft(logger=self.logger)
                    except Exception as err_reg:
                        self.error(f"[generaptor ERROR] {str(err_reg)}")
                if self.config["run"]["generaptor"].get("usnjrnl", False):
                    self.info("[generaptor] Run UsnJrnl")
                    try:
                        self.generaptor_parse_usnjrnl(logger=self.logger)
                    except Exception as err_reg:
                        self.error(f"[generaptor ERROR] {str(err_reg)}")
                if self.config["run"]["generaptor"].get("prefetch", False):
                    self.info("[generaptor] Run Prefetch")
                    try:
                        self.generaptor_parse_prefetch(logger=self.logger)
                    except Exception as err_reg:
                        self.error(f"[generaptor ERROR] {str(err_reg)}")
                if self.config["run"]["generaptor"].get("mplog", False):
                    self.info("[generaptor] Run MPLog")
                    try:
                        self.generaptor_parse_mplog(logger=self.logger)
                    except Exception as err_reg:
                        self.error(f"[generaptor ERROR] {str(err_reg)}")
                if self.config["run"]["generaptor"].get("activitiescache", False):
                    self.info("[generaptor] Run ActivitiesCache")
                    try:
                        self.generaptor_parse_activitiescache(logger=self.logger)
                    except Exception as err_reg:
                        self.error(f"[generaptor ERROR] {str(err_reg)}")
                if self.config["run"]["generaptor"].get("recyclebin", False):
                    self.info("[generaptor] Run Recycle Bin")
                    try:
                        self.generaptor_parse_recyclebin(logger=self.logger)
                    except Exception as err_reg:
                        self.error(f"[generaptor ERROR] {str(err_reg)}")
                if self.config["run"]["generaptor"].get("psreadline", False):
                    self.info("[generaptor] Run PSReadline")
                    try:
                        self.generaptor_get_consolehost_history(logger=self.logger)
                    except Exception as err_reg:
                        self.error(f"[generaptor ERROR] {str(err_reg)}")
                if self.config["run"]["generaptor"].get("iis", False):
                    self.info("[generaptor] Run IIS")
                    try:
                        res = self.get_iis_logs(logger=self.logger)
                    except Exception as err_reg:
                        self.error(f"[generaptor ERROR] {str(err_reg)}")
                    if self.is_logstash_active:
                        self.send_iis_logs(iis_logs=res, logger=self.logger)
                if self.config["run"]["generaptor"].get("timeline", False):
                    self.info("[generaptor] Run PLASO")
                    self.check_docker_image(
                        image_name=self.docker_images["plaso"]["image"],
                        tag=self.docker_images["plaso"]["tag"],
                        logger=self.logger,
                    )
                    self.generate_plaso_timeline(logger=self.logger)
        except Exception as ex:
            self.error(f"[generaptor ERROR] {str(ex)}")
            self.info("Exception so kill my running containers")
            self.kill_docker_container(logger=self.logger)
            raise ex
        finally:
            self.info("[generaptor] End processing")
