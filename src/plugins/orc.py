import os
import docker
import re
import time
from src.thirdparty import triageutils as triageutils
from src.thirdparty.ParseEVTX import ParseEVTX
from src.thirdparty.ParseRegistry import ParseRegistry
from src.thirdparty.ParsePrefetch import ParsePrefetch
from src.thirdparty.ParseMFT.mft_analyzer import MftAnalyzer
from logging import Logger
from pathlib import Path
from src import BasePlugin


class Plugin(BasePlugin):
    """
    Plugin pour triage de collecte générée par ORC
    """

    def __init__(self, conf: dict):
        super().__init__(config=conf)
        self.input_archive = Path(
            os.path.join(self.upload_dir, conf["archive"]["name"])
        )
        self.private_key_file = Path(
            os.path.join(self.upload_dir, conf["run"]["orc"]["private_key_file"])
        )

        self.orc_dir = Path(os.path.join(self.upload_dir, self.hostname, "orc"))
        triageutils.create_directory_path(path=self.orc_dir, logger=self.logger)

        self.zip_destination = Path(os.path.join(self.orc_dir, "extract"))
        triageutils.create_directory_path(path=self.zip_destination, logger=self.logger)

        self.config["general"]["extracted_zip"] = f"{self.zip_destination}"
        _updt = triageutils.update_config_file(
            data=self.config,
            conf_file=f'{self.config["general"]["extract"]}/config.yaml',
            logger=self.logger,
        )

        self.parsed_share = Path(os.path.join(self.orc_dir, "pytriage_parsed_files"))
        triageutils.create_directory_path(path=self.parsed_share, logger=self.logger)

        self.plaso_folder = os.path.join(self.orc_dir, "pytriage_plaso")
        triageutils.create_directory_path(path=self.plaso_folder, logger=self.logger)

    @triageutils.LOG
    def check_docker_image(self, image_name: str, tag: str, logger: Logger):
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
            self.logger.error(f"[check_docker_image] {ex}")
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
    def rename_orc_file(self, filepath: Path, logger: Logger):
        """
        Rename file by keeping only real file name

        return:
            Path: file's new path
        """
        try:
            _new_name = filepath.name
            _path = filepath.parent

            _pattern = re.compile(r"_\{.*\}.data$")
            if _pattern.search(_new_name):
                _new_name = re.sub(_pattern, "", _new_name)

            _pattern = re.compile(r"^[A-Fa-f0-9]+_[A-Fa-f0-9]+_[A-Fa-f0-9]+_[0-9]{1}_")
            if _pattern.search(_new_name):
                _new_name = re.sub(_pattern, "", _new_name)

            _new_path = Path(_path) / Path(_new_name)

            if triageutils.file_exists(file=_new_path, LOGLEVEL="NOLOG"):
                self.info(f"[rename_orc_file] File exists !")
                _parent = Path(_path) / Path(str(round(time.time() * 1000)))
                triageutils.create_directory_path(path=_parent, LOGLEVEL="NOLOG")
                _new_path = _parent / Path(_new_name).name
            triageutils.move_file(
                src=filepath, dst=_new_path, logger=self.logger, LOGLEVEL="NOLOG"
            )
            return _new_path
        except Exception as ex:
            self.error(f"[rename_orc_file] {ex}")
            return ""

    @triageutils.LOG
    def extract_orc_archive(self, archive: Path, dest: Path, logger: Logger):
        try:
            if archive.name.endswith(".7z.p7b"):
                res, _decrypted_archive = triageutils.decrypt_orc_archive(
                    archive=archive,
                    dest=dest,
                    private_key=self.private_key_file,
                    logger=self.logger,
                )
                if not res:
                    raise Exception("Error in decrypt ORC archive")
            else:
                _decrypted_archive = archive
            if _decrypted_archive.name.endswith(".7z"):
                res = triageutils.extract_7z_archive(
                    archive=_decrypted_archive, dest=dest, logger=self.logger
                )
                self.logger.info(f"[extract_orc_archive] extract_7z_archive: {res}")
            else:
                raise Exception("Not a valid 7z ORC archive")
        except Exception as ex:
            self.logger.error(f"[extract_orc_archive] {ex}")
            raise ex

    @triageutils.LOG
    def extract_all_7z(self, logger: Logger):
        try:
            records = list()
            for _7z in triageutils.search_files_by_extension_generator(
                src=self.zip_destination, extension=".7z", logger=self.logger
            ):
                _extract_to = self.orc_dir / Path(_7z.stem)
                if triageutils.directory_exists(dir=_extract_to, logger=self.logger):
                    triageutils.delete_directory(src=_extract_to, logger=self.logger)
                res = triageutils.extract_7z_archive(
                    archive=_7z, dest=_extract_to, logger=self.logger
                )
            for _file in triageutils.search_files_by_extension_generator(
                src=self.orc_dir, extension=".data", logger=self.logger
            ):
                records.append(self.rename_orc_file(filepath=_file, logger=self.logger))
            return records
        except Exception as ex:
            self.error(f"[extract_all_7z] {str(ex)}")
            return records

    @triageutils.LOG
    def get_evtx(self, evtx_folder: Path, logger: Logger) -> list:
        """Copie les fichiers evtx présents dans le dossier vers le dossier partagé.
        Args:
            evtx_folder (Path): chemin du dossier contenant les fichiers evtx si pas de dossier, il cherche dans tout le vhdx
        Returns:
            un tableau contenant les chemins de tous les fichiers trouvés
        """
        records = list()
        records.extend(
            triageutils.search_files_by_extension(
                dir=evtx_folder, extension=".evtx", logger=self.logger
            )
        )
        return records

    @triageutils.LOG
    def send_logs_to_winlogbeat(self, evtx_logs: list, logger: Logger) -> bool:
        """Copie les evtx vers le dossier partagé sur la VM Winlogbeat.
        Args:
            evtx_logs (list):Chemins des fichiers de log
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
            if triageutils.directory_exists(dir=win_log_path, logger=self.logger):
                triageutils.delete_directory(src=win_log_path, logger=self.logger)
            if triageutils.create_directory_path(path=win_log_path, logger=self.logger):
                self.info(
                    f"[send_logs_to_winlogbeat] WinLogBeat created: {win_log_path}"
                )
                result &= triageutils.copy_files(
                    src=evtx_logs, dst=win_log_path, logger=self.logger
                )
        except Exception as ex:
            self.error(f"[send_logs_to_winlogbeat] {ex}")
        self.info(f"[send_logs_to_winlogbeat] result: {result}")
        return result

    @triageutils.LOG
    def orc_parse_evtx(self, evtx_logs: list, logger: Logger):
        try:
            _ip = self.logstash_url
            if _ip.startswith("http"):
                _ip = self.logstash_url.split("//")[1]
            _count = 0
            evtx_parsed_share = Path(os.path.join(self.parsed_share, "EVTX_parsed"))
            triageutils.create_directory_path(
                path=evtx_parsed_share, logger=self.logger
            )
            for _f in evtx_logs:
                _count += 1
                self.info(f"[orc_parse_evtx] Process File {_count}/{len(evtx_logs)}")
                _p = ParseEVTX(
                    evtxfilepath=Path(_f),
                    ip=_ip,
                    port=self.evtxparser_port,
                    client=self.clientname,
                    hostname=self.hostname,
                    mapping=self.evtx_mapping,
                    output_folder=evtx_parsed_share,
                    logstash_is_active=self.is_logstash_active,
                    logger=self.logger,
                )
                _res = _p.parse_evtx()
                self.info(f"[orc_parse_evtx] {_res}")
        except Exception as ex:
            self.error(f"[orc_parse_evtx] {str(ex)}")
            raise ex

    @triageutils.LOG
    def orc_parse_registry(self, logger: Logger):
        try:
            # _reg_files = self.get_registry_files(logger=self.logger)
            _reg_share = Path(os.path.join(self.parsed_share, "REGISTRY_parsed"))
            triageutils.create_directory_path(path=_reg_share, logger=self.logger)
            _parse_reg = ParseRegistry(logger=self.logger)
            _parse_reg.parse_all(dir_to_reg=self.orc_dir, out_folder=_reg_share)
        except Exception as ex:
            self.error(f"[orc_parse_registry] {str(ex)}")
            raise ex

    @triageutils.LOG
    def orc_parse_mft(self, logger: Logger):
        try:
            _mft_files = triageutils.search_files(
                src=self.orc_dir, pattern="$MFT", strict=True
            )
            if len(_mft_files):
                _output_file = f"{self.parsed_share}/mft_parsed.csv"
                _mft = _mft_files[0]
                _analyzer = MftAnalyzer(
                    mft_file=_mft, output_file=_output_file, logger=self.logger
                )
                _analyzer.analyze()
            else:
                self.logger.error(f"[orc_parse_mft] No $MFT found")
        except Exception as ex:
            self.error(f"[orc_parse_mft] {str(ex)}")
            raise ex

    @triageutils.LOG
    def process_USN(self, logger: Logger):
        try:
            records = list()
            _usnfodler = self.orc_dir / Path("USNInfo")
            records = triageutils.search_files(
                src=_usnfodler, pattern="USNInfo", logger=self.logger
            )
            if len(records):
                _usn_share = Path(os.path.join(self.parsed_share, "USN_parsed"))
                triageutils.create_directory_path(path=_usn_share, logger=self.logger)
                triageutils.copy_files(src=records, dst=_usn_share, logger=self.logger)
        except Exception as ex:
            self.error(f"[get_USN_file] {str(ex)}")

    @triageutils.LOG
    def get_prefetch(self, prefetch_dir: Path, logger: Logger):
        """
        Extract PREFETCH files from archive generated by orc to prefetch folder and rename them

        Returns:
            List[Path]: prefetch with new filenames
        """
        records = list()
        records.extend(
            triageutils.search_files(
                src=prefetch_dir, pattern=".pf", logger=self.logger
            )
        )
        return records

    @triageutils.LOG
    def orc_parse_prefetch(self, logger: Logger):
        try:
            _artefacts = self.orc_dir / Path("Artefacts") / Path("Prefetch")
            _prefetch_share = Path(os.path.join(self.parsed_share, "Prefetch_parsed"))
            triageutils.create_directory_path(path=_prefetch_share, logger=self.logger)

            for _f in self.get_prefetch(prefetch_dir=_artefacts, logger=self.logger):
                _f = Path(_f)
                _output_file = _prefetch_share / Path(f"{_f.stem}.json")
                _analyzer = ParsePrefetch(
                    prefetch=_f,
                    output=_output_file,
                    logger=self.logger,
                )
                _analyzer.analyze()
        except Exception as ex:
            self.error(f"[orc_parse_prefetch] {str(ex)}")
            raise ex

    @triageutils.LOG
    def generate_plaso_timeline(self, logger: Logger):
        """Génère la timeline PLASO.
        Args:

        Returns:

        """
        try:
            _docker = docker.from_env()
            if triageutils.file_exists(
                file=f"{self.orc_dir}/{self.hostname}.plaso",
            ):
                triageutils.delete_file(
                    src=f"{self.orc_dir}/{self.hostname}.plaso",
                )
            self.info(f"Docker volume to mount: {self.data_volume}")
            self.info("Start Docker log2timeline/plaso all parsers")
            cmd = [
                "log2timeline.py",
                "--storage_file",
                f"{self.orc_dir}/{self.hostname}.plaso",
                f"{self.orc_dir}",
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
                src=os.path.join(self.orc_dir, f"{self.hostname}.plaso"),
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
    def run(self, logger: Logger):
        """Fonction principale qui exécute tout le triage de orc

        Args:

        Returns:

        """
        try:
            self.extract_orc_archive(
                archive=self.input_archive,
                dest=self.zip_destination,
                logger=self.logger,
            )
            self.extract_all_7z(logger=self.logger)
            if self.config["run"]["orc"]["evtx"]:
                try:
                    self.info("[orc] Run EVTX")
                    _evtxfolder = self.orc_dir / Path("Event")
                    _evtx_files = self.get_evtx(
                        evtx_folder=_evtxfolder, logger=self.logger
                    )
                    if self.config["run"]["orc"]["winlogbeat"]:
                        if self.is_winlogbeat_active:
                            self.send_logs_to_winlogbeat(
                                evtx_logs=_evtx_files, logger=self.logger
                            )
                    else:
                        self.orc_parse_evtx(evtx_logs=_evtx_files, logger=self.logger)
                except Exception as ex:
                    self.error(f"[Orc ERROR] {str(ex)}")
            if self.config["run"]["orc"]["registry"]:
                try:
                    self.info("[orc] Run Registry")
                    self.orc_parse_registry(logger=self.logger)
                except Exception as ex:
                    self.error(f"[Orc ERROR] {str(ex)}")
            if self.config["run"]["orc"]["mft"]:
                try:
                    self.info("[orc] Run MFT")
                    self.orc_parse_mft(logger=self.logger)
                except Exception as ex:
                    self.error(f"[Orc ERROR] {str(ex)}")
            if self.config["run"]["orc"]["usnjrnl"]:
                try:
                    self.info("[orc] Run UsnJrnl")
                    self.process_USN(logger=self.logger)
                except Exception as ex:
                    self.error(f"[Orc ERROR] {str(ex)}")
            if self.config["run"]["orc"]["prefetch"]:
                try:
                    self.info("[orc] Run Prefetch")
                    self.orc_parse_prefetch(logger=self.logger)
                except Exception as ex:
                    self.error(f"[Orc ERROR] {str(ex)}")
            if self.config["run"]["orc"]["mplog"]:
                self.info("[orc] Run MPLog -- NOT DONE YET")
            if self.config["run"]["orc"]["iis"]:
                self.info("[orc] Run IIS -- NOT DONE YET")
            if self.config["run"]["orc"]["timeline"]:
                self.info("[orc] Run PLASO")
                self.check_docker_image(
                    image_name=self.docker_images["plaso"]["image"],
                    tag=self.docker_images["plaso"]["tag"],
                    logger=self.logger,
                )
                self.generate_plaso_timeline(logger=self.logger)
        except Exception as ex:
            self.error(f"[orc ERROR] {str(ex)}")
            self.info("Exception so kill my running containers")
            self.kill_docker_container(logger=self.logger)
            raise ex
        finally:
            self.info("[orc] End processing")
