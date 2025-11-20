import os
import yaml
import time
import json
import subprocess
from re import compile
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
from src.thirdparty.ParseRDPCache import BMCContainer
from src.thirdparty.ParseLnk import ParseLnk
from src.thirdparty.ParseJumpList import ParseJumpList
from src.thirdparty.ParseTask import ParseTask
from src.thirdparty.ParseWebCache import ParseWebcache
from src.thirdparty.wrapper_docker import WrapperDocker
from logging import Logger
from src import BasePlugin, Status
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


class Plugin(BasePlugin):
    """
    GENERAPTOR plugin pour triage du ZIP
    """

    def __init__(self, conf: dict):
        super().__init__(config=conf)
        self.zipfile = Path(os.path.join(self.upload_dir, conf["archive"]["name"]))
        self._docker = WrapperDocker(logger=self.logger)

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
        self.update_config_file(data=self.config)

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

        self.plaso_folder = Path(os.path.join(self.generaptor_dir, "plaso"))
        triageutils.create_directory_path(path=self.plaso_folder, logger=self.logger)

        self.filebeat_dir = Path(os.path.join(self.generaptor_dir, "filebeat"))
        triageutils.create_directory_path(path=self.filebeat_dir, logger=self.logger)

        self.activitiescache_share = Path(
            os.path.join(self.generaptor_dir, "ActivitiesCache")
        )
        triageutils.create_directory_path(
            path=self.activitiescache_share, logger=self.logger
        )

        self.recyclebin_dir = Path(os.path.join(self.generaptor_dir, "RecycleBin"))
        triageutils.create_directory_path(path=self.recyclebin_dir, logger=self.logger)

        self.psreadline_dir = Path(os.path.join(self.generaptor_dir, "PSReadLine"))
        triageutils.create_directory_path(path=self.psreadline_dir, logger=self.logger)

        self.RDPCache_dir = Path(os.path.join(self.generaptor_dir, "RDPCache"))
        triageutils.create_directory_path(path=self.RDPCache_dir, logger=self.logger)

        self.lnk_dir = Path(os.path.join(self.generaptor_dir, "Lnk"))
        triageutils.create_directory_path(path=self.lnk_dir, logger=self.logger)

        self.jumplist_dir = Path(os.path.join(self.generaptor_dir, "JumpList"))
        triageutils.create_directory_path(path=self.jumplist_dir, logger=self.logger)

        self.tasks_dir = Path(os.path.join(self.generaptor_dir, "Tasks"))
        triageutils.create_directory_path(path=self.tasks_dir, logger=self.logger)

        self.webcache_dir = Path(os.path.join(self.generaptor_dir, "WebCache"))
        triageutils.create_directory_path(path=self.webcache_dir, logger=self.logger)

        self.hayabusa_dir = Path(os.path.join(self.generaptor_dir, "Hayabusa"))
        triageutils.create_directory_path(path=self.hayabusa_dir, logger=self.logger)

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
    def extract_to(self, directory: Path, secret: str, logger: Logger) -> bool:
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
    def _check_same_fingerprint(self, private_key: Path, logger: Logger):
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
    ) -> bool:
        if not self._check_same_fingerprint(
            private_key=private_key, logger=self.logger
        ):
            return False
        try:
            private_key = self.load_private_key(private_key, private_key_secret)
        except ValueError as ex:
            self.error("invalid private key and/or passphrase")
            self.error(ex)
            return False
        try:
            secret = self._secret(private_key)
        except ValueError:
            self.error("private key does not match collection archive")
            return False
        dirname = self.hostname  # f"{archive.stem}"
        directory = output_directory / dirname
        directory.mkdir(parents=True, exist_ok=True)
        self.info(f"extracting: {archive}")
        self.info(f"        to: {directory}")
        self.extract_to(directory=directory, secret=secret, logger=None)
        return True

    @triageutils.LOG
    def generate_plaso_timeline(self, logger: Logger) -> Path:
        """Génère la timeline de PLASO.
        Args:

        Returns:
            plaso file path (Path)
        """
        try:
            if triageutils.file_exists(
                file=f"{self.zip_destination}/{self.hostname}.plaso",
            ):
                triageutils.delete_file(
                    src=f"{self.zip_destination}/{self.hostname}.plaso",
                )
            cmd = [
                "log2timeline.py",
                "--storage_file",
                f"{self.zip_destination}/{self.hostname}.plaso",
                f"{self.zip_destination}/{self.hostname}/uploads",
            ]
            self._docker.image = f'{self.docker_images["plaso"]["image"]}:{self.docker_images["plaso"]["tag"]}'
            if not self._docker.is_image_present(name=self._docker.image):
                raise Exception("Image not present")
            self._docker.container = f"{self.uuid}-plaso"
            self._docker.volumes = [f"{self.data_volume}:/data"]
            self._docker.execute_cmd(cmd=cmd)
            s_file = self.plaso_folder / f"{self.hostname}.plaso"
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
            return s_file
        except Exception as ex:
            self.error(f"[generate_plaso_timeline] {ex}")
            raise ex

    @triageutils.LOG
    def generate_psort_timeline(self, plasofile: Path, logger: Logger) -> Path:
        """Génère la timeline avec PSORT du fichier plaso en entrée et l'envoie à ELK.
        Args:
            plasofile (str): chemin du fichier plaso à parser

        Returns:
            (str) file path généré

        """
        try:
            cmd = [
                "psort.py",
                "-o",
                "json_line",
                "-a",
                "-w",
                f"{self.plaso_folder.as_posix()}/psort-{self.hostname}.jsonl",
                plasofile.as_posix(),
            ]
            self._docker.image = f'{self.docker_images["plaso"]["image"]}:{self.docker_images["plaso"]["tag"]}'
            if not self._docker.is_image_present(name=self._docker.image):
                raise Exception("Image not present")
            self._docker.container = f"{self.uuid}-psort"
            self._docker.volumes = [f"{self.data_volume}:/data"]
            self._docker.execute_cmd(cmd=cmd)
            s_file = self.plaso_folder / f"psort-{self.hostname}.jsonl"
            return s_file
        except Exception as ex:
            self.error(f"[generate_psort_timeline] {ex}")
            raise ex

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
                port=self.psort_port,  # TODO define port
                extrafields=extrafields,
                logger=self.logger,
            )
        except Exception as e:
            self.error(f"[send_psort_to_elk] {str(e)}")
            raise e

    @triageutils.LOG
    def generaptor_evtx_winlogbeat(self, logger: Logger):
        try:
            win_log_path = os.path.join(self.winlogbeat, self.clientname, self.hostname)
            triageutils.create_directory_path(path=win_log_path, logger=self.logger)
            for _f in self.zip_destination.rglob("*.evtx"):
                if _f.is_file():
                    #triageutils.copy_file(
                    #    src=_f, dst=self.evtx_share, overwrite=True, logger=None
                    #)
                    triageutils.copy_file(
                        src=_f, dst=win_log_path, overwrite=True, logger=None
                    )
        except Exception as ex:
            self.error(f"[generaptor_evtx_winlogbeat] {ex}")
            raise ex

    @triageutils.LOG
    def generaptor_iis_logs(self, logger: Logger):
        try:
            _found = False
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "inetpub/**/*.log".lower()
            )
            for _f in self.zip_destination.rglob(_searchpattern):
                if _f.is_file():
                    _found = True
                    triageutils.copy_file(
                        src=_f, dst=self.iis_share, overwrite=True, logger=self.logger
                    )

            if _found and self.is_logstash_active:
                _data = triageutils.generate_iis_filebeat_config(
                    ip=self.logstash_url.split("//")[1],
                    port=self.iis_port,
                    client=self.clientname,
                    hostname=self.hostname,
                    logger=None,
                )
                new_config = self.filebeat_dir / Path("filebeat.docker.yml")
                with open(new_config.as_posix(), "w") as file:
                    yaml.dump(_data, file, sort_keys=False)
                voldisk = [
                    f"{new_config}:/usr/share/filebeat/filebeat.yml:ro",
                ]
                voldisk.append(f"{self.iis_share}:/iis")
                cmd = ["filebeat", "-e", "--once", "--strict.perms=false"]
                self._docker.image = f'{self.docker_images["filebeat"]["image"]}:{self.docker_images["filebeat"]["tag"]}'
                self._docker.container = f"{self.uuid}-filebeat-iis"
                self._docker.volumes = voldisk
                self._docker.execute_cmd(cmd=cmd)
        except Exception as ex:
            self.error(f"[generaptor_iis_logs] {ex}")
            raise ex

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
                        log_dir = os.path.join(self.filebeat_dir.as_posix(), folder)
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
            new_config = self.filebeat_dir / Path("filebeat.docker.yml")
            with open(new_config.as_posix(), "w") as file:
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
            elk_file = self.filebeat_dir / Path("filebeat.docker.yml")
            if not triageutils.file_exists(file=elk_file, logger=self.logger):
                raise Exception("cannot generate filebeat yaml not present")
            voldisk = [
                f"{elk_file.as_posix()}:/usr/share/filebeat/filebeat.yml:ro",
            ]
            for k, v in self.log_dirs.items():
                voldisk.append(f"{v}:/tmp/{k}")
            self.info(f"VolDirs: {voldisk}")
            cmd = ["filebeat", "-e", "--once", "--strict.perms=false"]
            self._docker.image = f'{self.docker_images["filebeat"]["image"]}:{self.docker_images["filebeat"]["tag"]}'
            if not self._docker.is_image_present(name=self._docker.image):
                raise Exception("Image not present")
            self._docker.container = f"{self.uuid}-filebeat"
            self._docker.volumes = voldisk
            self._docker.execute_cmd(cmd=cmd)
        except Exception as ex:
            self.error(f"[generaptor_filebeat] {str(ex)}")
            raise ex

    @triageutils.LOG
    def generaptor_parse_evtx(self, logger: Logger):
        try:
            _ip = self.logstash_url
            if _ip.startswith("http"):
                _ip = self.logstash_url.split("//")[1]
            for _f in self.zip_destination.rglob("*.evtx"):
                if _f.is_file():
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
                    self.info(f"[generaptor_parse_evtx] Parse: {_f}")
                    _res = _p.parse_evtx()
                    self.info(f"[generaptor_parse_evtx] Result: {_res}")
                    # send analytics info
                    if self.is_logstash_active:
                        _file_infos = triageutils.get_file_informations(filepath=_f)
                        _analytics = triageutils.generate_analytics(logger=self.logger)
                        _analytics["log"]["file"]["eventcount"] = _res.setdefault(
                            "nb_events_read", 0
                        )
                        _analytics["log"]["file"]["eventsent"] = _res.setdefault(
                            "nb_events_sent", 0
                        )
                        _analytics["log"]["file"]["path"] = str(_f)
                        _analytics["log"]["file"]["size"] = _file_infos.setdefault(
                            "fileSize", 0
                        )
                        _analytics["log"]["file"]["lastaccessed"] = (
                            _file_infos.setdefault("lastAccessTime", 0)
                        )
                        _analytics["log"]["file"]["creation"] = _file_infos.setdefault(
                            "creationTime", 0
                        )
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
            for _f in self.zip_destination.rglob("$MFT"):
                if _f.is_file():
                    _output_file = f"{self.ntfs_share}/{_f.parts[-2]}_mft.csv"
                    # _output_file = f"{self.ntfs_share}/mft_parsed_{int(time.time())}.csv"
                    _analyzer = MftAnalyzer(
                        mft_file=_f.as_posix(),
                        output_file=_output_file,
                        logger=self.logger,
                    )
                    _analyzer.analyze()
        except Exception as ex:
            self.error(f"[generaptor_parse_mft] {str(ex)}")
            raise ex

    @triageutils.LOG
    def generaptor_parse_usnjrnl(self, logger: Logger):
        try:
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "$UsnJrnl*$J".lower()
            )
            for _f in self.zip_destination.rglob(_searchpattern):
                if _f.is_file():
                    _csv_output_file = self.ntfs_share / f"{_f.parts[-2]}_usn.csv"
                    _body_output_file = self.ntfs_share / f"{_f.parts[-2]}_usn.body"
                    # _csv_output_file = self.ntfs_share / f"usn_parsed_{int(time.time())}.csv"
                    # _body_output_file = self.ntfs_share / f"usn_parsed_{int(time.time())}.body"
                    _analyzer = ParseUSNJRNL(
                        usn_file=_f,
                        result_csv_file=_csv_output_file,
                        result_body_file=_body_output_file,
                        logger=self.logger,
                    )
                    _analyzer.analyze()
        except Exception as ex:
            self.error(f"[generaptor_parse_usnjrnl] {str(ex)}")
            raise ex

    @triageutils.LOG
    def generaptor_parse_prefetch(self, logger: Logger):
        try:
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "Prefetch/**/*.pf".lower()
            )
            for _f in self.zip_destination.rglob(_searchpattern):
                if _f.is_file():
                    _output_file = self.prefetch_share / f"{_f.name}.json"
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
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "MPLog-*".lower()
            )
            for _f in self.zip_destination.rglob(_searchpattern):
                self.info(f"[generaptor_parse_mplog] Parse: {_f}")
                _analyzer = ParseMPLog(mplog_file=_f, output_directory=self.mplog_share)
                _analyzer.orchestrator()
        except Exception as ex:
            self.error(f"[generaptor_parse_mplog] {str(ex)}")
            raise ex

    @triageutils.LOG
    def generaptor_parse_activitiescache(self, logger: Logger):
        try:
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl,
                "ConnectedDevicesPlatform/**/ActivitiesCache.db".lower(),
            )
            for _f in self.zip_destination.rglob(_searchpattern):
                if _f.is_file():
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
            # _recyclebin_folder = triageutils.get_folder_path_by_name(
            #     folder_name="$Recycle.Bin",
            #     root=self.zip_destination,
            #     logger=self.logger,
            # )
            # if _recyclebin_folder:
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "$Recycle.Bin".lower()
            )
            for _recyclebin_folder in self.zip_destination.rglob(_searchpattern):
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
                    _output = self.recyclebin_dir / f"{_dir.name}.csv"
                    trash.write_csv(csv_file=_output)
                    _output = self.recyclebin_dir / f"{_dir.name}.jsonl"
                    trash.write_jsonl(jsonl_file=_output)
        except Exception as ex:
            self.error(f"[generaptor_parse_recyclebin] {ex}")

    @triageutils.LOG
    def generaptor_get_consolehost_history(self, logger: Logger):
        try:
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "ConsoleHost_history.txt".lower()
            )
            for _f in self.zip_destination.rglob(_searchpattern):
                if _f.is_file():
                    self.info(f"[generaptor_get_consolehost_history] Parse: {_f}")
                    try:
                        _username = _f.parts[_f.parts.index("Users") + 1]
                    except Exception as errorname:
                        self.error(f"File not in Users folders: {errorname}")
                        _username = time.time()
                    _dst = self.psreadline_dir / str(_username)
                    triageutils.copy_file(
                        src=_f, dst=_dst, overwrite=True, logger=self.logger
                    )
        except Exception as ex:
            self.error(f"[generaptor_get_consolehost_history] {str(ex)}")
            raise ex

    @triageutils.LOG
    def generaptor_get_RDPCache(self, logger: Logger):
        try:
            for _d in [f for f in self.RDPCache_dir.iterdir() if f.is_dir()]:
                triageutils.delete_directory(src=_d, logger=self.logger)
            # Get BMC files
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "Terminal Server Client/**/*.bmc".lower()
            )
            for _f in self.zip_destination.rglob(_searchpattern):
                if _f.is_file():
                    try:
                        _username = _f.parts[_f.parts.index("Users") + 1]
                    except Exception as errorname:
                        self.error(f"{errorname}")
                        _username = time.time()
                    _dst = self.RDPCache_dir / str(_username)
                    triageutils.copy_file(
                        src=_f, dst=_dst, overwrite=True, logger=self.logger
                    )
            # Get BIN files
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "Terminal Server Client/**/*.bin".lower()
            )
            for _f in self.zip_destination.rglob(_searchpattern):
                if _f.is_file():
                    try:
                        _username = _f.parts[_f.parts.index("Users") + 1]
                    except Exception as errorname:
                        self.error(f"{errorname}")
                        _username = time.time()
                    _dst = self.RDPCache_dir / str(_username)
                    triageutils.copy_file(
                        src=_f, dst=_dst, overwrite=True, logger=self.logger
                    )
            # Exec parser on subdirectories
            for _d in [f for f in self.RDPCache_dir.iterdir() if f.is_dir()]:
                try:
                    _extract_folder = _d / Path("parsed")
                    triageutils.create_directory_path(path=_extract_folder, logger=None)
                    _bmcc = BMCContainer(logger=self.logger)
                    for _cache_file in [
                        _temp_file
                        for _temp_file in _d.iterdir()
                        if _temp_file.is_file()
                    ]:
                        try:
                            self.logger.info(
                                f"[generaptor_get_RDPCache] Processing file: {_cache_file}"
                            )
                            if _bmcc.b_import(_cache_file):
                                _bmcc.b_process()
                                _bmcc.b_export(_extract_folder)
                                _bmcc.b_flush()
                        except Exception as ex:
                            self.error(f"[bmcc #1] {str(ex)}")
                except Exception as ex:
                    self.error(f"[bmcc #2] {str(ex)}")
        except Exception as ex:
            self.error(f"[generaptor_get_RDPCache] {str(ex)}")
            raise ex

    @triageutils.LOG
    def generaptor_parse_lnk(self, logger: Logger):
        try:
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "Recent/**/*.lnk".lower()
            )
            for _f in self.zip_destination.rglob(_searchpattern):
                if _f.is_file():
                    try:
                        _username = _f.parts[_f.parts.index("Users") + 1]
                    except Exception as errorname:
                        self.error(f"File not in Users folders: {errorname}")
                        _username = time.time()
                    _dst = self.lnk_dir / str(_username)
                    triageutils.create_directory_path(path=_dst, logger=None)
                    _output_file = _dst / f"{_f.stem}.json"
                    _analyzer = ParseLnk(
                        lnk_file=_f,
                        output=_output_file,
                        logger=self.logger,
                    )
                    _analyzer.analyze()
        except Exception as ex:
            self.error(f"[generaptor_parse_lnk] {str(ex)}")
            raise ex

    @triageutils.LOG
    def generaptor_parse_jumplist(self, logger: Logger):
        try:
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl,
                "Recent/**/*.automaticDestinations-ms".lower(),
            )
            for _f in self.zip_destination.rglob(_searchpattern):
                if _f.is_file():
                    try:
                        _username = _f.parts[_f.parts.index("Users") + 1]
                    except Exception as errorname:
                        self.error(f"File not in Users folders: {errorname}")
                        _username = time.time()
                    _dst = self.jumplist_dir / str(_username)
                    triageutils.create_directory_path(path=_dst, logger=None)
                    _output_file = _dst / f"{_f.name}.jsonl"
                    _analyzer = ParseJumpList(
                        input_file=_f,
                        output_file=_output_file,
                        logger=self.logger,
                    )
                    _analyzer.analyze_automatic_destinations()
            _searchpatterncustom = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "Recent/**/*.customDestinations-ms".lower()
            )
            for _f in self.zip_destination.rglob(_searchpatterncustom):
                if _f.is_file():
                    try:
                        _username = _f.parts[_f.parts.index("Users") + 1]
                    except Exception as errorname:
                        self.error(f"File not in Users folders: {errorname}")
                        _username = time.time()
                    _dst = self.jumplist_dir / str(_username)
                    triageutils.create_directory_path(path=_dst, logger=None)
                    _output_file = _dst / f"{_f.name}.jsonl"
                    _analyzer = ParseJumpList(
                        input_file=_f,
                        output_file=_output_file,
                        logger=self.logger,
                    )
                    _analyzer.analyze_custom_destinations()
        except Exception as ex:
            self.error(f"[generaptor_parse_jumplist] {str(ex)}")
            raise ex

    @triageutils.LOG
    def generaptor_parse_tasks(self, logger: Logger):
        try:
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "System32/Tasks/*".lower()
            )
            for _f in self.zip_destination.rglob(_searchpattern):
                if _f.is_file():
                    try:
                        _output_file = self.tasks_dir / f"{_f.name}.json"
                        if triageutils.file_exists(file=_output_file, logger=None):
                            triageutils.delete_file(src=_output_file, logger=None)
                        _analyzer = ParseTask(
                            task_file=_f,
                            result_jsonl_file=_output_file,
                            logger=self.logger,
                        )
                        _analyzer.analyze()
                    except Exception as ex:
                        self.error(str(ex))
        except Exception as ex:
            self.error(f"[generaptor_parse_tasks] {str(ex)}")
            raise ex

    @triageutils.LOG
    def generaptor_parse_webcache(self, logger: Logger):
        try:
            _searchpattern = compile(r"[a-z]").sub(
                triageutils._ci_glob_repl, "WebCacheV01.dat".lower()
            )
            for _f in self.zip_destination.rglob(_searchpattern):
                if _f.is_file():
                    try:
                        try:
                            _username = _f.parts[_f.parts.index("Users") + 1]
                        except Exception as errorname:
                            self.error(f"File not in Users folders: {errorname}")
                            _username = time.time()
                        _output_jsonl_file = (
                            self.webcache_dir / f"{_username}_{_f.stem}.jsonl"
                        )
                        if triageutils.file_exists(
                            file=_output_jsonl_file, logger=None
                        ):
                            triageutils.delete_file(src=_output_jsonl_file, logger=None)
                        _analyzer = ParseWebcache(
                            cache_file=_f,
                            result_jsonl_file=_output_jsonl_file,
                            logger=self.logger,
                        )
                        _analyzer.analyze()
                    except Exception as ex:
                        self.error(str(ex))
        except Exception as ex:
            self.error(f"[generaptor_parse_webcache] {str(ex)}")
            raise ex

    @triageutils.LOG
    def generaptor_exec_hayabusa(self, logger: Logger) -> Path:
        """
        Execute Hayabusa on EVTX folder and return JSONL result Path
        """
        try:
            _evtx_folder = next(self.zip_destination.rglob("*.evtx"), None)
            if _evtx_folder:
                _evtx_folder.parent
                output_json = self.hayabusa_dir / "hayabusa.jsonl"
                cmd = [
                    self.hayabusa_bin_path,
                    "json-timeline",
                    "-d",
                    str(_evtx_folder.parent),
                    "-p",
                    "all-field-info-verbose",
                    "-ULwqNC",
                    "-o",
                    str(output_json),
                ]
                p = subprocess.Popen(
                    cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=os.environ
                )
                (output, err) = p.communicate()
                p_status = p.wait()

                # self.info(f"[hayabusa] output: {output}")
                self.info(f"[generaptor_exec_hayabusa] error: {err}")
                self.info(f"[generaptor_exec_hayabusa] status: {p_status}")
                if not triageutils.file_exists(file=output_json, logger=self.logger):
                    raise Exception("hayabusa no result generated")
                return self.hayabusa_dir / "hayabusa.jsonl"
            else:
                raise Exception("No evtx folder")
        except Exception as ex:
            self.error(f"[generaptor_exec_hayabusa] {ex}")
            raise ex

    @triageutils.LOG
    def generaptor_hayabusa_to_elk(self, hayabusa_results:Path, logger:Logger) -> int:
        """
        Fonction qui envoie les résultats hayabusa vers ELK
        Return:
            number of event sent (int)
        """
        try:
            with open(str(hayabusa_results), "r") as jsonl_f:
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
                                f"[generaptor_hayabusa_to_elk] Failed to change values type of AllFieldInfo: {haya_error}"
                            )
                if self.is_logstash_active:
                    ip = self.logstash_url
                    if ip.startswith("http"):
                        ip = self.logstash_url.split("//")[1]
                    extrafields = dict()
                    extrafields["csirt"] = dict()
                    extrafields["csirt"]["client"] = self.clientname
                    extrafields["csirt"]["application"] = "alerts"
                    extrafields["csirt"]["hostname"] = self.hostname

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
            self.error(f"[generaptor_hayabusa_to_elk] {str(e)}")
            raise e



    @triageutils.LOG
    def run(self, logger: Logger):
        """Fonction principale qui exécute tout le triage de generaptor

        Args:

        Returns:

        """
        try:
            _exceptions = list()
            self.update_workflow_status(
                plugin="generaptor", module="plugin", status=Status.STARTED
            )
            if not self._extract_cmd(
                archive=self.zipfile,
                private_key=self.private_key_file,
                output_directory=self.zip_destination,
                private_key_secret=self.private_key_secret,
                logger=self.logger,
            ):
                raise Exception("Error while extracting archive.")
            try:
                triageutils.copy_directory(
                    src=os.path.join(self.zip_destination, self.hostname, "results"),
                    dst=self.ntfs_share,
                )
            except Exception as copy_err:
                self.error(f"[RUN] {copy_err}")
                _exceptions.append(str(copy_err))
            if self.config["run"]["generaptor"].get("linux_filebeat", False):
                self.info("[generaptor] Run Linux Filebeat")
                self.get_linux_logs(logger=self.logger)
                if self.is_logstash_active:
                    self.update_workflow_status(
                        plugin="generaptor",
                        module="linux_filebeat",
                        status=Status.STARTED,
                    )
                    try:
                        self.ymlcreator(logger=self.logger)
                        self.generaptor_filebeat(logger=self.logger)
                        self.update_workflow_status(
                            plugin="generaptor",
                            module="linux_filebeat",
                            status=Status.FINISHED,
                        )
                    except Exception as ex:
                        self.error(f"[generaptor ERROR] {str(ex)}")
                        _exceptions.append(str(ex))
                        self.update_workflow_status(
                            plugin="generaptor",
                            module="linux_filebeat",
                            status=Status.ERROR,
                        )
                else:
                    raise Exception("logstash is not active")
            if self.config["run"]["generaptor"].get("linux_plaso", False):
                self.update_workflow_status(
                    plugin="generaptor", module="linux_plaso", status=Status.STARTED
                )
                self.info("[generaptor] Run Linux PLASO")
                try:
                    _linux_plaso_file = self.generate_plaso_timeline(logger=self.logger)
                    self.generate_psort_timeline(
                        plasofile=_linux_plaso_file, logger=self.logger
                    )
                    self.update_workflow_status(
                        plugin="generaptor",
                        module="linux_plaso",
                        status=Status.FINISHED,
                    )
                except Exception as ex:
                    self.error(f"[generaptor ERROR] {str(ex)}")
                    _exceptions.append(str(ex))
                    self.update_workflow_status(
                        plugin="generaptor", module="linux_plaso", status=Status.ERROR
                    )
            if self.config["run"]["generaptor"].get("winlogbeat", False):
                self.info("[generaptor] Run Winlogbeat")
                self.update_workflow_status(
                    plugin="generaptor", module="winlogbeat", status=Status.STARTED
                )
                try:
                    self.update_workflow_status(
                        plugin="generaptor",
                        module="winlogbeat",
                        status=Status.STARTED,
                    )
                    if self.is_winlogbeat_active:
                        self.generaptor_evtx_winlogbeat(logger=self.logger)
                        self.update_workflow_status(
                            plugin="generaptor",
                            module="winlogbeat",
                            status=Status.FINISHED,
                        )
                    else:
                        raise Exception("Winlogbeat not enabled")
                except Exception as ex:
                    self.error(f"[generaptor ERROR] {str(ex)}")
                    _exceptions.append(str(ex))
                    self.update_workflow_status(
                        plugin="generaptor",
                        module="winlogbeat",
                        status=Status.ERROR,
                    )
            if self.config["run"]["generaptor"].get("evtx", False):
                self.info("[generaptor] Run EVTX")
                self.update_workflow_status(
                    plugin="generaptor", module="evtx", status=Status.STARTED
                )
                try:
                    self.generaptor_parse_evtx(logger=self.logger)
                    self.update_workflow_status(
                        plugin="generaptor",
                        module="evtx",
                        status=Status.FINISHED,
                    )
                except Exception as ex:
                    self.error(f"[generaptor ERROR] {str(ex)}")
                    _exceptions.append(str(ex))
                    self.update_workflow_status(
                        plugin="generaptor", module="evtx", status=Status.ERROR
                    )
            if self.config["run"]["generaptor"].get("registry", False):
                self.info("[generaptor] Run Registry")
                self.update_workflow_status(
                    plugin="generaptor", module="registry", status=Status.STARTED
                )
                try:
                    self.generaptor_parse_registry(logger=self.logger)
                    self.update_workflow_status(
                        plugin="generaptor",
                        module="registry",
                        status=Status.FINISHED,
                    )
                except Exception as err_reg:
                    self.error(f"[generaptor ERROR] {str(err_reg)}")
                    _exceptions.append(str(err_reg))
                    self.update_workflow_status(
                        plugin="generaptor", module="registry", status=Status.ERROR
                    )
            if self.config["run"]["generaptor"].get("mft", False):
                self.info("[generaptor] Run MFT")
                self.update_workflow_status(
                    plugin="generaptor", module="mft", status=Status.STARTED
                )
                try:
                    self.generaptor_parse_mft(logger=self.logger)
                    self.update_workflow_status(
                        plugin="generaptor", module="mft", status=Status.FINISHED
                    )
                except Exception as err_reg:
                    self.error(f"[generaptor ERROR] {str(err_reg)}")
                    _exceptions.append(str(err_reg))
                    self.update_workflow_status(
                        plugin="generaptor", module="mft", status=Status.ERROR
                    )
            if self.config["run"]["generaptor"].get("usnjrnl", False):
                self.info("[generaptor] Run UsnJrnl")
                self.update_workflow_status(
                    plugin="generaptor", module="usnjrnl", status=Status.STARTED
                )
                try:
                    self.generaptor_parse_usnjrnl(logger=self.logger)
                    self.update_workflow_status(
                        plugin="generaptor",
                        module="usnjrnl",
                        status=Status.FINISHED,
                    )
                except Exception as err_reg:
                    self.error(f"[generaptor ERROR] {str(err_reg)}")
                    _exceptions.append(str(err_reg))
                    self.update_workflow_status(
                        plugin="generaptor", module="usnjrnl", status=Status.ERROR
                    )
            if self.config["run"]["generaptor"].get("prefetch", False):
                self.info("[generaptor] Run Prefetch")
                self.update_workflow_status(
                    plugin="generaptor", module="prefetch", status=Status.STARTED
                )
                try:
                    self.generaptor_parse_prefetch(logger=self.logger)
                    self.update_workflow_status(
                        plugin="generaptor",
                        module="prefetch",
                        status=Status.FINISHED,
                    )
                except Exception as err_reg:
                    self.error(f"[generaptor ERROR] {str(err_reg)}")
                    _exceptions.append(str(err_reg))
                    self.update_workflow_status(
                        plugin="generaptor", module="prefetch", status=Status.ERROR
                    )
            if self.config["run"]["generaptor"].get("mplog", False):
                self.info("[generaptor] Run MPLog")
                self.update_workflow_status(
                    plugin="generaptor", module="mplog", status=Status.STARTED
                )
                try:
                    self.generaptor_parse_mplog(logger=self.logger)
                    self.update_workflow_status(
                        plugin="generaptor", module="mplog", status=Status.FINISHED
                    )
                except Exception as err_reg:
                    self.error(f"[generaptor ERROR] {str(err_reg)}")
                    _exceptions.append(str(err_reg))
                    self.update_workflow_status(
                        plugin="generaptor", module="mplog", status=Status.ERROR
                    )
            if self.config["run"]["generaptor"].get("activitiescache", False):
                self.info("[generaptor] Run ActivitiesCache")
                self.update_workflow_status(
                    plugin="generaptor",
                    module="activitiescache",
                    status=Status.STARTED,
                )
                try:
                    self.generaptor_parse_activitiescache(logger=self.logger)
                    self.update_workflow_status(
                        plugin="generaptor",
                        module="activitiescache",
                        status=Status.FINISHED,
                    )
                except Exception as err_reg:
                    self.error(f"[generaptor ERROR] {str(err_reg)}")
                    _exceptions.append(str(err_reg))
                    self.update_workflow_status(
                        plugin="generaptor",
                        module="activitiescache",
                        status=Status.ERROR,
                    )
            if self.config["run"]["generaptor"].get("recyclebin", False):
                self.info("[generaptor] Run Recycle Bin")
                self.update_workflow_status(
                    plugin="generaptor", module="recyclebin", status=Status.STARTED
                )
                try:
                    self.generaptor_parse_recyclebin(logger=self.logger)
                    self.update_workflow_status(
                        plugin="generaptor",
                        module="recyclebin",
                        status=Status.FINISHED,
                    )
                except Exception as err_reg:
                    self.error(f"[generaptor ERROR] {str(err_reg)}")
                    _exceptions.append(str(err_reg))
                    self.update_workflow_status(
                        plugin="generaptor",
                        module="recyclebin",
                        status=Status.ERROR,
                    )
            if self.config["run"]["generaptor"].get("psreadline", False):
                self.info("[generaptor] Run PSReadline")
                self.update_workflow_status(
                    plugin="generaptor", module="psreadline", status=Status.STARTED
                )
                try:
                    self.generaptor_get_consolehost_history(logger=self.logger)
                    self.update_workflow_status(
                        plugin="generaptor",
                        module="psreadline",
                        status=Status.FINISHED,
                    )
                except Exception as err_reg:
                    self.error(f"[generaptor ERROR] {str(err_reg)}")
                    _exceptions.append(str(err_reg))
                    self.update_workflow_status(
                        plugin="generaptor",
                        module="psreadline",
                        status=Status.ERROR,
                    )
            if self.config["run"]["generaptor"].get("rdpcache", False):
                self.info("[generaptor] Run RDPCache")
                self.update_workflow_status(
                    plugin="generaptor", module="rdpcache", status=Status.STARTED
                )
                try:
                    self.generaptor_get_RDPCache(logger=self.logger)
                    self.update_workflow_status(
                        plugin="generaptor",
                        module="rdpcache",
                        status=Status.FINISHED,
                    )
                except Exception as err_rdp:
                    self.error(f"[generaptor ERROR] {str(err_rdp)}")
                    _exceptions.append(str(err_rdp))
                    self.update_workflow_status(
                        plugin="generaptor", module="rdpcache", status=Status.ERROR
                    )
            if self.config["run"]["generaptor"].get("lnk", False):
                self.info("[generaptor] Run Lnk")
                self.update_workflow_status(
                    plugin="generaptor", module="lnk", status=Status.STARTED
                )
                try:
                    self.generaptor_parse_lnk(logger=self.logger)
                    self.update_workflow_status(
                        plugin="generaptor",
                        module="lnk",
                        status=Status.FINISHED,
                    )
                except Exception as err_lnk:
                    self.error(f"[generaptor ERROR] {str(err_lnk)}")
                    _exceptions.append(str(err_lnk))
                    self.update_workflow_status(
                        plugin="generaptor", module="lnk", status=Status.ERROR
                    )
            if self.config["run"]["generaptor"].get("jumplist", False):
                self.info("[generaptor] Run JumpList")
                self.update_workflow_status(
                    plugin="generaptor", module="jumplist", status=Status.STARTED
                )
                try:
                    self.generaptor_parse_jumplist(logger=self.logger)
                    self.update_workflow_status(
                        plugin="generaptor",
                        module="jumplist",
                        status=Status.FINISHED,
                    )
                except Exception as err_jumplist:
                    self.error(f"[generaptor ERROR] {str(err_jumplist)}")
                    _exceptions.append(str(err_jumplist))
                    self.update_workflow_status(
                        plugin="generaptor", module="jumplist", status=Status.ERROR
                    )
            if self.config["run"]["generaptor"].get("tasks", False):
                self.info("[generaptor] Run Tasks")
                self.update_workflow_status(
                    plugin="generaptor", module="tasks", status=Status.STARTED
                )
                try:
                    self.generaptor_parse_tasks(logger=self.logger)
                    self.update_workflow_status(
                        plugin="generaptor",
                        module="tasks",
                        status=Status.FINISHED,
                    )
                except Exception as err_tasks:
                    self.error(f"[generaptor ERROR] {str(err_tasks)}")
                    _exceptions.append(str(err_tasks))
                    self.update_workflow_status(
                        plugin="generaptor", module="tasks", status=Status.ERROR
                    )
            if self.config["run"]["generaptor"].get("webcache", False):
                self.info("[generaptor] Run WebCache")
                self.update_workflow_status(
                    plugin="generaptor", module="webcache", status=Status.STARTED
                )
                try:
                    self.generaptor_parse_webcache(logger=self.logger)
                    self.update_workflow_status(
                        plugin="generaptor",
                        module="webcache",
                        status=Status.FINISHED,
                    )
                except Exception as err_webcache:
                    self.error(f"[generaptor ERROR] {str(err_webcache)}")
                    _exceptions.append(str(err_webcache))
                    self.update_workflow_status(
                        plugin="generaptor", module="webcache", status=Status.ERROR
                    )
            if self.config["run"]["generaptor"].get("hayabusa", False):
                self.info("[generaptor] Run HAYABUSA")
                self.update_workflow_status(
                    plugin="generaptor", module="hayabusa", status=Status.STARTED
                )
                try:
                    _res = self.generaptor_exec_hayabusa(logger=self.logger)
                    if self.is_logstash_active:
                        self.generaptor_hayabusa_to_elk(hayabusa_results=_res, logger=self.logger)
                    self.update_workflow_status(
                        plugin="generaptor", module="hayabusa", status=Status.FINISHED
                    )
                except Exception as err_reg:
                    self.error(f"[generaptor ERROR] {str(err_reg)}")
                    _exceptions.append(str(err_reg))
                    self.update_workflow_status(
                        plugin="generaptor", module="hayabusa", status=Status.ERROR
                    )
            if self.config["run"]["generaptor"].get("iis", False):
                self.info("[generaptor] Run IIS")
                self.update_workflow_status(
                    plugin="generaptor", module="iis", status=Status.STARTED
                )
                try:
                    self.generaptor_iis_logs(logger=self.logger)
                    self.update_workflow_status(
                        plugin="generaptor", module="iis", status=Status.FINISHED
                    )
                except Exception as err_reg:
                    self.error(f"[generaptor ERROR] {str(err_reg)}")
                    _exceptions.append(str(err_reg))
                    self.update_workflow_status(
                        plugin="generaptor", module="iis", status=Status.ERROR
                    )
            if self.config["run"]["generaptor"].get("plaso", False):
                self.info("[generaptor] Run PLASO")
                self.update_workflow_status(
                    plugin="generaptor", module="plaso", status=Status.STARTED
                )
                try:
                    _plaso_file = self.generate_plaso_timeline(logger=self.logger)
                    if not self.is_timesketch_active:
                        self.generate_psort_timeline(plasofile=_plaso_file,logger=self.logger)
                    self.update_workflow_status(
                        plugin="generaptor",
                        module="plaso",
                        status=Status.FINISHED,
                    )
                except Exception as err_reg:
                    self.error(f"[generaptor ERROR] {str(err_reg)}")
                    _exceptions.append(str(err_reg))
                    self.update_workflow_status(
                        plugin="generaptor", module="plaso", status=Status.ERROR
                    )
            if len(_exceptions) > 0:
                raise Exception(str(_exceptions))
            self.update_workflow_status(
                plugin="generaptor", module="plugin", status=Status.FINISHED
            )
        except Exception as ex:
            self.update_workflow_status(
                plugin="generaptor", module="plugin", status=Status.ERROR
            )
            self.error(f"[generaptor ERROR] {str(ex)}")
            raise ex
        finally:
            self._docker.kill_containers_by_name(name=self.uuid)
            self.info("[generaptor] End processing")
