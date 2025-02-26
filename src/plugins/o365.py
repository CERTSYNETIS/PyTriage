import os
import json
from pathlib import Path
from src.thirdparty import triageutils as triageutils
from src import BasePlugin


class Plugin(BasePlugin):
    """
    O365 plugin pour triage
    """

    def __init__(self, conf=None):
        super().__init__(config=conf)
        self.o365_dir = os.path.join(self.upload_dir, self.hostname, "o365")
        triageutils.create_directory_path(path=self.o365_dir, logger=self.logger)
        self.o365_archive = os.path.join(self.upload_dir, conf["archive"]["name"])

    @triageutils.LOG
    def o365_extract_zip(self, archive=None, dest=None, specific_files=[], logger=None):
        """Extrait tous les fichiers de l'archive ZIP o365.

        Args:
            archive (str): optionnel chemin complet du fichier zip
            dest (str): optionnel chemin complet de décompression de l'archive
            specific_files (tab): optionnel tableau avec le nom de fichier spécifiques à extraire
        """
        try:
            if not archive:
                archive = self.o365_archive
            if not dest:
                dest = self.o365_dir
            self.info(f"Zip file: {archive}")
            self.info(f"Dest folder: {dest}")
            triageutils.extract_zip_archive(
                archive=archive,
                dest=dest,
                specific_files=specific_files,
                logger=self.logger,
            )
        except Exception as ex:
            self.logger.error(f"[o365_extract_zip] {ex}")
            raise ex

    @triageutils.LOG
    def o365_get_json_files(self, logger=None) -> list:
        """Fonction qui récupère les fichiers json de l'archive o365"""
        records = []
        try:
            records.extend(
                triageutils.search_files_by_extension(
                    dir=self.o365_dir, extension=".json", logger=self.logger
                )
            )
        except Exception as e:
            self.error(f"[o365_parse_files] {str(e)}")
            raise e
        finally:
            self.info(f"Files found: {len(records)}")
        return records

    @triageutils.LOG
    def o365_get_csv_files(self, logger=None) -> list:
        """Fonction qui récupère les fichiers csv de l'archive o365"""
        records = []
        try:
            records.extend(
                triageutils.search_files_by_extension(
                    dir=self.o365_dir, extension=".csv", logger=self.logger
                )
            )
        except Exception as e:
            self.error(f"[o365_parse_files] {str(e)}")
            raise e
        finally:
            self.info(f"Files found: {len(records)}")
        return records

    @triageutils.LOG
    def o365_send_json_results(self, json_file=None, logger=None):
        """Fonction qui envoie les résultats json o365 vers ELK"""
        try:
            extrafields = dict()
            extrafields["csirt"] = dict()
            extrafields["csirt"]["client"] = self.clientname.lower()
            extrafields["csirt"]["application"] = json_file.stem.lower()
            extrafields["csirt"]["hostname"] = self.hostname.lower()
            ip = self.logstash_url
            if ip.startswith("http"):
                ip = self.logstash_url.split("//")[1]
            triageutils.send_jsonl_to_elk(
                filepath=json_file,
                ip=ip,
                port=self.o365_port,
                logger=self.logger,
                extrafields=extrafields,
            )
        except Exception as e:
            self.error(f"[o365_send_json_results] {str(e)}")
            raise e

    @triageutils.LOG
    def is_jsonl_file(self, input_file: Path) -> bool:
        try:
            with open(input_file, "r", encoding="utf-8-sig") as jsonl_f:
                json_data = [json.loads(line) for line in jsonl_f]
            return True
        except Exception as e:
            self.info(f"[is_jsonl_file] {input_file} Not a JSONL file")
            return False

    @triageutils.LOG
    def run(self, logger=None):
        """Fonction principale qui exécute les plugins de parsing o365

        Args:

        Returns:

        """
        try:
            self.o365_extract_zip(
                archive=self.o365_archive, dest=self.o365_dir, logger=self.logger
            )
            _files = self.o365_get_json_files(logger=self.logger)
            _files.extend(self.o365_get_csv_files(logger=self.logger))
            _total = len(_files)
            _count = 0
            for f in _files:
                _count += 1
                f = Path(f)
                if f.suffix.lower() == ".csv":
                    # process csv files
                    _jsonl_file = Path(f"{os.path.splitext(f)[0]}.jsonl")
                    triageutils.csv_to_json(
                        csvFilePath=f,
                        jsonFilePath=_jsonl_file,
                        delimiter=",",
                        writeToFile=True,
                        writeasjsonline=True,
                        logger=self.logger,
                    )
                    f = _jsonl_file
                else:
                    if not self.is_jsonl_file(input_file=f):
                        _jsonl_file = Path(f"{os.path.splitext(f)[0]}.jsonl")
                        if triageutils.convert_json_to_jsonl(
                            input_file=f, output_file=_jsonl_file, logger=self.logger
                        ):
                            f = _jsonl_file
                self.info(f"[o365] send file {_count}/{_total}")
                self.o365_send_json_results(json_file=f, logger=self.logger)

        except Exception as ex:
            self.error(f"[o365] run {str(ex)}")
            raise ex
