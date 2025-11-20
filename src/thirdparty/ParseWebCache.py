from pathlib import Path
import json
from struct import unpack
from uuid import UUID
from pyesedb import open_file_object, column_types
from datetime import datetime, timedelta, timezone
from logging import Logger

REF_OLE = datetime(1899, 12, 30, tzinfo=timezone.utc)
REF_WIN32 = datetime(1601, 1, 1, tzinfo=timezone.utc)
_COLUMN_TYPE_PARSE_FUNC_MAPPING = {
    column_types.GUID: lambda r, i: str(UUID(bytes=r.get_value_data(i))),
    column_types.TEXT: lambda r, i: r.get_value_data_as_string(i),
    column_types.BOOLEAN: lambda r, i: r.get_value_data_as_boolean(i),
    column_types.DATE_TIME: lambda r, i: from_ole_timestamp(
        unpack("d", r.get_value_data(i))[0] * 24 * 60 * 60 * 1000000
    ).isoformat(),
    column_types.LARGE_TEXT: lambda r, i: r.get_value_data_as_string(i),
    column_types.BINARY_DATA: lambda r, i: r.get_value_data(i).decode("utf-8"),
    column_types.LARGE_BINARY_DATA: lambda r, i: r.get_value_data(i).decode("utf-8"),
    column_types.SUPER_LARGE_VALUE: lambda r, i: r.get_value_data(i).decode("utf-8"),
    column_types.FLOAT_32BIT: lambda r, i: unpack("f", r.get_value_data(i))[0],
    column_types.DOUBLE_64BIT: lambda r, i: unpack("d", r.get_value_data(i))[0],
    column_types.INTEGER_8BIT_UNSIGNED: lambda r, i: unpack("B", r.get_value_data(i))[
        0
    ],
    column_types.INTEGER_16BIT_SIGNED: lambda r, i: unpack("h", r.get_value_data(i))[0],
    column_types.INTEGER_16BIT_UNSIGNED: lambda r, i: unpack("H", r.get_value_data(i))[
        0
    ],
    column_types.INTEGER_32BIT_SIGNED: lambda r, i: unpack("i", r.get_value_data(i))[0],
    column_types.INTEGER_32BIT_UNSIGNED: lambda r, i: unpack("I", r.get_value_data(i))[
        0
    ],
    column_types.INTEGER_64BIT_SIGNED: lambda r, i: unpack("q", r.get_value_data(i))[0],
}


def from_ole_timestamp(microseconds: int) -> datetime:
    """OLE microseconds timestamp as datetime"""
    return REF_OLE + timedelta(microseconds=microseconds)


def from_win32_timestamp(microseconds: int) -> datetime:
    """WIN32 microseconds timestamp as datetime"""
    return REF_WIN32 + timedelta(microseconds=microseconds)


class ParseWebcache:
    """
    Class to Parse Windows webcache
    """

    def __init__(
        self,
        cache_file: Path,
        result_jsonl_file: Path,
        logger: Logger,
    ) -> None:
        self.cache_file = cache_file
        self.result_jsonl_file = result_jsonl_file
        self.logger = logger

    def write_results(self, json_data: dict, output_file: Path):
        with open(output_file, "a", encoding="utf-8", errors="ignore") as jsonfile:
            json.dump(json_data, jsonfile)
            jsonfile.write("\n")

    def get_record_value(self, record, col, index):
        try:
            parse = _COLUMN_TYPE_PARSE_FUNC_MAPPING.get(col.type)
            if not record:
                return ""
            value = parse(record, index)
            if value:
                if col.name.endswith("Time"):
                    return from_win32_timestamp(value / 10).isoformat()
                if isinstance(value, bytes):
                    return value.decode(errors="ignore")
                return value
            return ""
        except Exception as ex:
            return "Err"

    def parse_webcache_database(self, filepath: Path):
        try:
            with open(filepath, "rb") as fd:
                webcache = open_file_object(fd)
                if webcache:
                    for table in webcache.tables:
                        if table.name.startswith("Container"):
                            _cols = [_col for _col in table.columns]
                            for rec in table.records:
                                _res = {
                                    column.name: self.get_record_value(
                                        rec, column, index
                                    )
                                    for index, column in enumerate(_cols)
                                }
                                _res["table"] = table.name
                                yield _res
        except Exception as ex:
            self.logger.error(f"[parse_webcache_database] {ex}")

    def analyze(self):
        try:
            self.logger.info(f"[analyze] Processing Webcache {self.cache_file}")
            for _data in self.parse_webcache_database(self.cache_file):
                self.write_results(json_data=_data, output_file=self.result_jsonl_file)
        except Exception as ex:
            self.logger.error(f"[analyze] {ex}")
