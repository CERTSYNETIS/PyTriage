#!/usr/bin/env python
from __future__ import division, unicode_literals

from collections import OrderedDict
from ._util import approximate_date
from .Trash import inspect
from glob import glob
from pathlib import Path
from logging import Logger
import os, csv, json

FORMAT = {
    "csv": "get_csv_string",
    "json": "get_json_string",
    "html": "get_html_string",
}


class TrashParse(object):
    def __init__(self, recyclebin_folder: Path, logger: Logger):
        self.files = list()
        self.path = recyclebin_folder
        self._results = OrderedDict()
        self._logger = logger

    def listfile(self):
        try:
            self.files.extend(
                glob(os.path.join(self.path, "INFO2*[! ]"))
                + glob(os.path.join(self.path, "$I*[! ]"))
            )
        except Exception as ex:
            self._logger.error(f"[listfile] {ex}")
            self.files = list()

    def parsefile(self) -> OrderedDict:
        try:
            for file in self.files:
                fileinfo = inspect(file)
                filename = fileinfo.basename

                if fileinfo.index_type == "INFO2":
                    continue  # Not implemented yet
                else:
                    self._results[filename] = fileinfo
            return self._results
        except Exception as ex:
            self._logger.error(f"[parsefile] {ex}")
            self._results = OrderedDict()
            return self._results

    def write_csv(self, csv_file: Path):
        try:
            # delete_file(src=csv_file, logger=self._logger)
            _data = list()
            for name, fileinfo in self._results.items():
                _row = dict()
                _row["name"] = name
                _row["DeletedTime"] = approximate_date(fileinfo.deleted_time)
                _row["filesize"] = fileinfo.filesize
                _row["type"] = fileinfo.type
                _row["version"] = fileinfo.version
                _row["original_path"] = fileinfo.original_path
                _data.append(_row)
            with open(csv_file, "w", newline="") as csvfile:
                fieldnames = [
                    "name",
                    "DeletedTime",
                    "filesize",
                    "type",
                    "version",
                    "original_path",
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(_data)
        except Exception as ex:
            self._logger.error(f"[write_csv] {ex}")

    def write_jsonl(self, jsonl_file: Path):
        try:
            # delete_file(src=jsonl_file, logger=self._logger)
            _data = list()
            for name, fileinfo in self._results.items():
                _row = dict()
                _row["name"] = name
                _row["datetime"] = approximate_date(fileinfo.deleted_time)
                _row["filesize"] = fileinfo.filesize
                _row["type"] = fileinfo.type
                _row["version"] = fileinfo.version
                _row["original_path"] = fileinfo.original_path
                _data.append(_row)
            with open(jsonl_file, "w", encoding="utf-8") as jsonf:
                for _entry in _data:
                    json.dump(_entry, jsonf)
                    jsonf.write("\n")
        except Exception as ex:
            self._logger.error(f"[write_jsonl] {ex}")
