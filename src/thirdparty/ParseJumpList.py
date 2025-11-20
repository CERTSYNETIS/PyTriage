import io
import struct
import olefile
import pylnk3
import codecs
from datetime import datetime, timedelta
from pathlib import Path
from .triageutils import file_exists, delete_file
from logging import Logger


def ansi_decoder(name):
    if name.lower() == "ansi":
        return codecs.lookup("cp1252")
    return None


codecs.register(ansi_decoder)


class ParseJumpList:
    def __init__(self, input_file: Path, output_file: Path, logger: Logger):

        self.input_file = input_file
        self.output_file = output_file
        self.logger = logger

    def write_results(self, data: list, output_file: Path):
        with open(output_file, "w", encoding="utf-8") as jsonfile:
            for line in data:
                jsonfile.write(f"{line}\n")

    def windows_filetime_to_dt(self, filetime):
        """Convertit un FILETIME Windows en datetime Python"""
        if filetime == 0:
            return None
        us = filetime / 10
        try:
            return datetime(1601, 1, 1) + timedelta(microseconds=us)
        except Exception:
            return None

    def parse_destlist(self, data) -> list:
        """
        Parse la structure DestList d'un fichier automaticDestinations
        (cf. format reverse-engineered par Eric Zimmerman & forensicswiki)
        """
        results = []
        header_size = 28  # 32
        if len(data) < header_size:
            return results
        # Header
        version, nr_entries, _, _, _ = struct.unpack("<IQQII", data[:header_size])
        offset = header_size
        entry_size = 114  # Taille fixe d'une entrée DestList (Win7+)
        idx = 0
        while offset + entry_size <= len(data):
            entry = data[offset : offset + entry_size]
            try:
                (
                    checksum,
                    birth_droid1,
                    birth_droid2,
                    dest_droid1,
                    dest_droid2,
                    last_mod_time,
                    pin_status,
                    counter,
                    _,
                ) = struct.unpack("<Q16s16s16s16sQIIQ", entry[:96])
                dt = self.windows_filetime_to_dt(last_mod_time)

                results.append(
                    {
                        "checksum": checksum,
                        "last_modification_time": dt,
                        "pin_status": pin_status,
                        "counter": counter,
                        "birth_droid": birth_droid1.hex(),
                        "dest_droid": dest_droid1.hex(),
                    }
                )
            except Exception as e:
                self.logger.error(f"[parse_destlist] Error parsing DestList: {e}")
            offset += entry_size
            idx += 1
        return results

    def parse_automatic_destinations(self, file_path: Path) -> list[dict]:
        """Parse .automaticDestinations-ms"""
        try:
            self.logger.info(f"[+] Parsing Automatic {file_path}")
            if not olefile.isOleFile(file_path.as_posix()):
                raise Exception(f"{file_path.as_posix()} is not a valid OLE")
            _res = list()
            ole = olefile.OleFileIO(file_path.as_posix())
            for stream in ole.listdir():
                if "DestList" in stream:
                    try:
                        data = ole.openstream(stream).read()
                        entries = self.parse_destlist(data)
                        for e in entries:
                            _counter = e.get("counter", "N/A")
                            _last_modification_time = e.get(
                                "last_modification_time", "N/A"
                            )
                            _birth_droid = e.get("birth_droid", "N/A")
                            _dest_droid = e.get("dest_droid", "N/A")
                    except Exception as err_destlist:
                        self.logger.error(
                            f"[parse_automatic_destinations] Error parsing DestList : {err_destlist}"
                        )
                elif all(part.isdigit() for part in stream):
                    try:
                        lnk_data = ole.openstream(stream).read()
                        lnk_stream = io.BytesIO(lnk_data)
                        lnk = pylnk3.parse(lnk_stream)
                        _path = str(getattr(lnk, "path", "N/A"))
                        _arguments = str(getattr(lnk, "arguments", "N/A"))
                        _description = str(getattr(lnk, "description", "N/A"))
                        _working_dir = str(getattr(lnk, "working_dir", "N/A"))
                        _ctime = str(getattr(lnk, "creation_time", "N/A"))
                        _atime = str(getattr(lnk, "access_time", "N/A"))
                        _res.append(
                            {
                                "path": _path,
                                "arguments": _arguments,
                                "description": _description,
                                "working_dir": _working_dir,
                                "ctime": _ctime,
                                "atime": _atime,
                            }
                        )
                    except Exception as e:
                        self.logger.error(
                            f"[parse_automatic_destinations] Error parsing LNK : {e}"
                        )
            return _res
        except Exception as ex:
            self.logger.error(f"[parse_automatic_destinations] {ex}")
            return []

    def parse_custom_destinations(self, file_path: Path) -> list[dict]:
        """Parse .customDestinations-ms (séquence de LNK concaténés)"""
        try:
            _res = list()
            with open(file_path, "rb") as f:
                content = f.read()
            self.logger.info(f"[+] Parsing Custom {file_path} ({len(content)} octets)")
            offset = 0
            lnk_index = 0
            while offset < len(content):
                try:
                    lnk_stream = io.BytesIO(content[offset:])
                    try:
                        lnk = pylnk3.parse(lnk_stream)
                    except Exception:
                        offset += 4  # seek if no valid header
                        continue
                    _path = str(getattr(lnk, "path", "N/A"))
                    _arguments = str(getattr(lnk, "arguments", "N/A"))
                    _description = str(getattr(lnk, "description", "N/A"))
                    _working_dir = str(getattr(lnk, "working_dir", "N/A"))
                    _ctime = str(getattr(lnk, "creation_time", "N/A"))
                    _atime = str(getattr(lnk, "access_time", "N/A"))
                    _res.append(
                        {
                            "path": _path,
                            "arguments": _arguments,
                            "description": _description,
                            "working_dir": _working_dir,
                            "ctime": _ctime,
                            "atime": _atime,
                        }
                    )
                    if hasattr(lnk, "raw"):
                        offset += len(lnk.raw)
                    else:
                        next_pos = content.find(b"\x4c\x00\x00\x00", offset + 4)
                        if next_pos == -1:
                            break
                        offset = next_pos
                    lnk_index += 1
                except Exception as ex:
                    self.logger.error(f"[-] [parse_custom_destinations] {ex}")
                    offset += 4
            return _res
        except Exception as finex:
            self.logger.error(f"[parse_custom_destinations] {finex}")
            return list()

    def analyze_automatic_destinations(self):
        try:
            _res = self.parse_automatic_destinations(file_path=self.input_file)
            if file_exists(file=self.output_file, logger=None):
                delete_file(src=self.output_file, logger=None)
            self.write_results(data=_res, output_file=self.output_file)
        except Exception as ex:
            self.logger.error(f"[analyze_automatic_destinations] --- {ex}")

    def analyze_custom_destinations(self):
        try:
            _res = self.parse_custom_destinations(file_path=self.input_file)
            if file_exists(file=self.output_file, logger=None):
                delete_file(src=self.output_file, logger=None)
            self.write_results(data=_res, output_file=self.output_file)
        except Exception as ex:
            self.logger.error(f"[analyze_custom_destinations] --- {ex}")
