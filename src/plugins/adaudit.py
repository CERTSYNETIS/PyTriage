import subprocess
import os
import json
import csv
import datetime
import asyncio
from src.thirdparty import triageutils as triageutils
from src import BasePlugin
import logging
from charset_normalizer import detect


class Plugin(BasePlugin):
    """
    ADAUDIT plugin pour triage
    """

    def __init__(self, conf: dict):
        super().__init__(config=conf)
        self.audit_date = datetime.date.today().strftime("%d-%m-%Y")
        self.adaudit_dir = os.path.join(self.upload_dir, self.audit_date, "adaudit")
        triageutils.create_directory_path(path=self.adaudit_dir, logger=self.logger)
        self.adaudit_archive = os.path.join(self.upload_dir, conf["archive"]["name"])
        self.info(f"Files found: {self.adaudit_archive}")

    @triageutils.LOG
    def adaudit_extract_zip(
        self, archive=None, dest=None, specific_files=[], logger=None
    ):
        """Extrait tous les fichiers de l'archive ZIP o365.

        Args:
            archive (str): optionnel chemin complet du fichier zip
            dest (str): optionnel chemin complet de décompression de l'archive
            specific_files (tab): optionnel tableau avec le nom de fichier spécifiques à extraire
        """
        try:
            if not archive:
                archive = self.adaudit_archive
            if not dest:
                dest = self.adaudit_dir
            self.info(f"Zip file: {archive}")
            self.info(f"Dest folder: {dest}")
            triageutils.extract_zip_archive(
                archive=archive,
                dest=dest,
                specific_files=specific_files,
                logger=self.logger,
            )
        except Exception as ex:
            self.logger.error(f"[adaudit_extract_zip] {ex}")
            raise ex

    @triageutils.LOG
    def adaudit_get_files(self, logger=None) -> dict:
        """
        Fonction qui récupère les fichiers txt, csv, json de l'archive adaudit
        """
        records = {"csv": [], "txt": []}
        for e in records.keys():
            try:
                records[e].extend(
                    triageutils.search_files_by_extension(
                        src=self.adaudit_dir, extension=e, logger=self.logger
                    )
                )
            except Exception as exc:
                self.error(f"[adaudit_get_files] {str(exc)}")
                raise exc
            finally:
                self.info(f"Files of ext {e} found: {len(records[e])}")
        return records

    @triageutils.LOG
    def send_to_elk(self, json_data: list = [], logger=None, extrafields: dict = {}):
        """Fonction qui envoie les résultats ADTimeline vers ELK"""
        try:
            ip = self.logstash_url
            if ip.startswith("http"):
                ip = self.logstash_url.split("//")[1]
            triageutils.send_data_to_elk(
                data=json_data,
                ip=ip,
                port=self.adaudit_port,
                logger=self.logger,
                extrafields=extrafields,
            )
        except Exception as e:
            self.error(f"[send_to_elk] {str(e)}")
            raise e

    @triageutils.LOG
    def eval_file(self, logger=None, file: str = None) -> dict:
        """
        Extraction des headers
        returns:
        - dict containing 'separator' and 'encoding'
        """
        separators = [b'","', b'";"', b'"|"']
        dialect = {"separator": ";", "encoding": "utf-8-sig"}
        blob = open(file, "rb").read(1024)
        result = detect(blob)

        if result["encoding"] is not None:
            dialect["encoding"] = result["encoding"]

        for pat in separators:
            if pat in blob:
                dialect["separator"] = chr(pat[1])
                break
        return dialect

    @triageutils.LOG
    def adaudit_translate_csv(self, logger=None, files: list = []) -> list:
        """
        Fonction de translation générique de CSV en jsonlines
        """
        try:
            extrafields = dict()
            extrafields["csirt"] = dict()
            extrafields["csirt"]["client"] = self.clientname.lower()
            extrafields["csirt"]["application"] = "adaudit"
            extrafields["csirt"]["hostname"] = self.hostname.lower()
            for sf in files:
                extrafields["file"] = triageutils.extract_file_name(
                    path=sf, extension="csv"
                )
                audit_jsonf = os.path.join(
                    self.adaudit_dir, f"{extrafields['file']['name']}.json"
                )
                dialect = self.eval_file(file=sf)
                res = triageutils.csv_to_json(
                    csvFilePath=sf,
                    jsonFilePath=audit_jsonf,
                    delimiter=dialect["separator"],
                    encoding=dialect["encoding"],
                    writeToFile=False,
                    extrafields=extrafields,
                    logger=self.logger,
                )
                if res:
                    self.send_to_elk(json_data=res, logger=self.logger)
                else:
                    pass
        except Exception as e:
            self.error(f"[adaudit_parse_results] Failure during parsing : {str(e)}")
            raise e

    @triageutils.LOG
    def adaudit_translate_txt(self, logger=None, files=list()) -> list:
        """
        Fonction de translation générique de CSV en jsonlines
        """
        try:
            extrafields = dict()
            extrafields["csirt"] = dict()
            extrafields["csirt"]["client"] = self.clientname.lower()
            extrafields["csirt"]["application"] = "adaudit"
            extrafields["csirt"]["hostname"] = self.hostname.lower()
            for sf in files:
                extrafields["file"] = triageutils.extract_file_name(
                    path=sf, extension="txt"
                )
                audit_jsonf = os.path.join(
                    self.adaudit_dir, f"{extrafields['file']['name']}.json"
                )
                res = triageutils.txt_to_json(
                    FilePath=sf,
                    jsonFilePath=audit_jsonf,
                    sanitize=False,
                    writeToFile=False,
                    extrafields=extrafields,
                    logger=self.logger,
                )
                if res:
                    self.send_to_elk(json_data=res, logger=self.logger)
                else:
                    self.error(f"[adaudit_parse_results] no data to send")
        except Exception as e:
            self.error(f"[adaudit_parse_results] Failure during parsing : {str(e)}")
            raise e

    @triageutils.LOG
    def run(self, logger=None):
        """Fonction principale qui exécute hayabusa

        Args:

        Returns:

        """
        try:
            self.adaudit_extract_zip(
                archive=self.adaudit_archive, dest=self.adaudit_dir, logger=self.logger
            )
            _files = dict()
            _files = self.adaudit_get_files(logger=self.logger)
            _total = sum([len(_files[x]) for x in _files.keys()])
            for e in _files.keys():
                _subtotal = len(_files[e])
                if e == "csv":
                    self.info(
                        f"[adaudit] translate from {e} to json : {_subtotal}/{_total}"
                    )
                    self.adaudit_translate_csv(logger=self.logger, files=_files[e])
                if e == "txt":
                    self.adaudit_translate_txt(logger=self.logger, files=_files[e])
                    self.info(
                        f"[adaudit] translate from {e} to json : {_subtotal}/{_total}"
                    )
                else:
                    self.info(f"[adaudit] Extension not yet supported, sorry")
        except Exception as ex:
            self.error(f"[adaudit] run {str(ex)}")
            raise ex
