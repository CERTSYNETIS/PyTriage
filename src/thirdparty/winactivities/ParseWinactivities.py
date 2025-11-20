import csv
import ujson
from pathlib import Path
from .activities import ActivitiesDb
from logging import Logger


class ParseWinActivities:
    def __init__(
        self,
        DBfilepath: Path,
        output_folder: Path,
        logger: Logger,
    ):
        self._DBfilepath = DBfilepath
        self.logger = logger
        self._output_folder = output_folder
        self._user_name = DBfilepath.parts[-2]

    def parse_file(self, dbfile: Path) -> dict:
        try:
            activities_db = ActivitiesDb(dbfile)
            _results = dict()
            for record in activities_db.iter_records():
                formatted_record = record.as_ordered_dict()
                _table = record._table
                if not _results.get(_table, None):
                    _results[_table] = dict()
                    _results[_table]["csv"] = list()
                    _results[_table]["jsonl"] = list()
                _elem = list()
                for _v in formatted_record.values():
                    try:
                        _elem.append(str(_v, "utf-8"))
                    except Exception as ex:
                        _elem.append(str(_v))
                _results[_table]["csv"].append(_elem)
                _results[_table]["jsonl"].append(
                    ujson.dumps(formatted_record, reject_bytes=False)
                )
            return _results
        except Exception as ex:
            self.logger.error(f"[parse_file] {ex}")
            return dict()

    def write_csv(self, content: dict, output_folder: Path):
        try:
            csv_header = {
                "Activity": [
                    "_rowid",
                    "Id",
                    "AppId",
                    "PackageIdHash",
                    "AppActivityId",
                    "ActivityType",
                    "ActivityStatus",
                    "ParentActivityId",
                    "Tag",
                    "Group",
                    "MatchId",
                    "LastModifiedTime",
                    "ExpirationTime",
                    "Payload",
                    "Priority",
                    "IsLocalOnly",
                    "PlatformDeviceId",
                    "CreatedInCloud",
                    "StartTime",
                    "EndTime",
                    "LastModifiedOnClient",
                    "GroupAppActivityId",
                    "ClipboardPayload",
                    "EnterpriseId",
                    "OriginalPayload",
                    "OriginalLastModifiedOnClient",
                    "ETag",
                ],
                "Activity_PackageId": [
                    "_rowid",
                    "ActivityId",
                    "Platform",
                    "PackageName",
                    "ExpirationTime",
                ],
                "Asset": ["Id, " "AssetPayload", "Status", "LastRefreshTime"],
                "ActivityOperation": [
                    "OperationOrder",
                    "Id",
                    "OperationType",
                    "AppId",
                    "PackageIdHash",
                    "AppActivityId",
                    "ActivityType",
                    "ParentActivityId",
                    "Tag",
                    "Group",
                    "MatchId",
                    "LastModifiedTime",
                    "ExpirationTime",
                    "Payload",
                    "Priority",
                    "CreatedTime",
                    "Attachments",
                    "PlatformDeviceId",
                    "CreatedInCloud",
                    "StartTime",
                    "EndTime",
                    "LastModifiedOnClient",
                    "CorrelationVector",
                    "GroupAppActivityId",
                    "ClipboardPayload",
                    "EnterpriseId",
                    "OriginalPayload",
                    "OriginalLastModifiedOnClient",
                    "ETag",
                ],
                "AppSettings": [],
                "ManualSequence": [],
                "DataEncryptionKeys": ["KeyVersion", "KeyValue", "CreatedInCloudTime"],
                "Metadata": ["Key", "Value"],
            }
            for _file in content.keys():
                csvfile = open(
                    output_folder / f"{self._user_name}_{_file}.csv",
                    "w",
                    newline="",
                    encoding="utf-8",
                )
                csv_writer = csv.writer(csvfile)
                csv_writer.writerow(csv_header.get(_file, []))
                _elems = content.get(_file, dict).get("csv", [])
                for _row in _elems:
                    csv_writer.writerow(_row)
        except Exception as ex:
            self.logger.error(f"[write_csv] {ex}")

    def write_json(self, content: dict, output_folder: Path):
        try:
            for _file in content.keys():
                with open(
                    output_folder / f"{self._user_name}_{_file}.jsonl", "w"
                ) as outfile:
                    _elems = content.get(_file, dict).get("jsonl", [])
                    for _row in _elems:
                        outfile.write(_row)
                        outfile.write("\n")
        except Exception as ex:
            self.logger.error(f"[write_json] {ex}")

    def process(self):
        try:
            _res = self.parse_file(dbfile=self._DBfilepath)
            self.write_csv(content=_res, output_folder=self._output_folder)
            self.write_json(content=_res, output_folder=self._output_folder)
        except Exception as ex:
            self.logger.error(f"[process] {ex}")
