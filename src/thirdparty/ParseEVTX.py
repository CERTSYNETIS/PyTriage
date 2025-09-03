import json
import Evtx.Evtx as evtx
import xmltodict
from pathlib import Path
import socket
from logging import Logger, getLogger
import re
from slugify import slugify
from datetime import datetime
from .triageutils import delete_file, file_exists


class ParseEVTX:
    """
    Parsing EVTX Files Class
    """

    def __init__(
        self,
        evtxfilepath: Path,
        ip: str,
        port: int,
        client: str,
        hostname: str,
        mapping: dict,
        output_folder: Path,
        logger: Logger,
        logstash_is_active: bool = False,
        analytics_port: int = 5050,
    ):
        self._evtx_file = evtxfilepath
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._ip = ip
        self._port = port
        self._analytics_port = analytics_port
        self._logstash_is_active = logstash_is_active
        self._client = client
        self._hostname = hostname
        self.logger = logger
        self._mapping = mapping
        self._output_folder = output_folder

    def send_to_elk(self, data: dict, extrafields: dict = {}):
        try:
            if not self._logstash_is_active:
                return
            data.update(extrafields)
            msg = f"{json.dumps(data)}\n"
            try:
                self._socket.sendall(msg.encode())
            except socket.error as err:
                if err.errno == 9:
                    self.logger.error(
                        f"[send_to_elk] socket probably closed try reconnect"
                    )
                    self._socket.close()
                    self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self._socket.connect((self._ip, self._port))
                    self._socket.sendall(msg.encode())
                else:
                    self.logger.error(f"[send_to_elk] socket: {err}")
            except Exception as ex:
                self.logger.error(f"[send_to_elk] {ex}")
        except Exception as ex:
            self.logger.error(f"[send_to_elk] {ex}")

    def parse_evtx_old(self) -> dict:
        try:
            extrafields = dict()
            extrafields["csirt"] = dict()
            extrafields["csirt"]["client"] = self._client
            extrafields["csirt"]["hostname"] = self._hostname
            _result = dict()
            _result["file"] = self._evtx_file.name
            _result["nb_events_read"] = 0
            _result["nb_events_sent"] = 0
            _index = 0

            # delete previous parsed file if it exists
            self.logger.info(f"Check if parsed file already exists...")
            delete_file(
                src=self._output_folder / f"{self._evtx_file.stem}.jsonl",
                logger=self.logger,
            )
            _jsonl_output = open(
                self._output_folder / f"{self._evtx_file.stem}.jsonl", "a"
            )
            self._socket.connect((self._ip, self._port))
            _events = list()
            with evtx.Evtx(self._evtx_file) as log:
                _evtxlogger = getLogger("Evtx")
                _evtxlogger.disabled = True
                _evtxlogger = getLogger("Evtx.Evtx")
                _evtxlogger.disabled = True
                _official_length = len(list(log.records()))
                _result["nb_events_read"] = _official_length
                self.logger.info(f"nb: {_official_length}")
                for record in log.records():
                    try:
                        _evt = record.lxml()
                        _system_tag = _evt.find("System", _evt.nsmap)
                        _time_created = _system_tag.find("TimeCreated", _evt.nsmap)
                        _eventid = _system_tag.find("EventID", _evt.nsmap).text
                        extrafields["csirt"]["application"] = re.sub(
                            r"-\d+", "-", slugify(self._evtx_file.stem.lower())
                        )
                        extrafields["csirt"]["file"] = self._evtx_file.name
                        data_dict = xmltodict.parse(record.xml())
                        data_dict["evtx_time"] = ""

                        if _time_created is not None:
                            data_dict["evtx_time"] = datetime.fromisoformat(
                                _time_created.get("SystemTime", "")
                            ).strftime("%Y-%m-%d %H:%M:%S")
                        if data_dict.get("Event", None) is not None:
                            data_dict["Event"]["description"] = "None"
                            if self._mapping.get(
                                re.sub(r"%\d+", "-", self._evtx_file.stem), None
                            ):
                                if self._mapping[
                                    re.sub(r"%\d+", "-", self._evtx_file.stem)
                                ].get(_eventid, None):
                                    data_dict["Event"]["description"] = self._mapping[
                                        re.sub(r"%\d+", "-", self._evtx_file.stem)
                                    ][_eventid]

                            if data_dict["Event"].get("System", None) is not None:
                                if (
                                    data_dict["Event"]["System"].get("EventID", None)
                                    is not None
                                ):
                                    data_dict["Event"]["System"]["EventID"] = _eventid

                        data_dict.update(extrafields)
                        self.send_to_elk(data=data_dict)
                        _events.append(data_dict)
                        json.dump(data_dict, _jsonl_output)
                        _jsonl_output.write("\n")
                        _index += 1
                    except Exception as ex:
                        self.logger.error(f"Error in record -- {ex}")
            _result["nb_events_sent"] = _index
        except Exception as ex:
            self.logger.error(f"err-- {self._evtx_file.stem}")
            self.logger.error(f"err-- {ex}")
        finally:
            if self._socket is not None:
                self._socket.close()
            if _jsonl_output:
                _jsonl_output.close
            return _result

    def parse_evtx(self) -> dict:
        try:
            extrafields = dict()
            extrafields["csirt"] = dict()
            extrafields["csirt"]["client"] = self._client
            extrafields["csirt"]["hostname"] = self._hostname

            _result = dict()
            _result["file"] = self._evtx_file.name
            _result["nb_events_read"] = 0
            _result["nb_events_sent"] = 0
            _index = 0

            # delete previous parsed file if it exists
            self.logger.info(f"Check if parsed file already exists...")
            if file_exists(
                file=self._output_folder / f"{self._evtx_file.stem}.jsonl",
                logger=self.logger,
            ):
                delete_file(
                    src=self._output_folder / f"{self._evtx_file.stem}.jsonl",
                    logger=self.logger,
                )
            _jsonl_output = open(
                self._output_folder / f"{self._evtx_file.stem}.jsonl", "a"
            )
            self._socket.connect((self._ip, self._port))
            _events = list()
            with evtx.Evtx(self._evtx_file) as log:
                _evtxlogger = getLogger("Evtx")
                _evtxlogger.disabled = True
                _evtxlogger = getLogger("Evtx.Evtx")
                _evtxlogger.disabled = True
                _official_length = len(list(log.records()))
                _result["nb_events_read"] = _official_length
                extrafields["csirt"]["application"] = re.sub(
                    r"-\d+", "-", slugify(self._evtx_file.stem.lower())
                )
                extrafields["csirt"]["file"] = self._evtx_file.name
                for record in log.records():
                    try:
                        _evt = record.lxml()
                        _system_tag = _evt.find("System", _evt.nsmap)
                        _time_created = _system_tag.find("TimeCreated", _evt.nsmap)
                        data_dict = dict()
                        data_dict["Description"] = ""
                        for _tag in [
                            "EventID",
                            "Version",
                            "Level",
                            "Task",
                            "Opcode",
                            "Keywords",
                            "EventRecordID",
                            "Channel",
                            "Computer",
                        ]:
                            if _system_tag.find(_tag, _evt.nsmap) is not None:
                                data_dict[_tag] = _system_tag.find(
                                    _tag, _evt.nsmap
                                ).text

                        data_dict["Timestamp"] = datetime.fromisoformat(
                            _time_created.get("SystemTime", "")
                        ).strftime("%d/%m/%Y %H:%M:%S")
                        _original_dict = xmltodict.parse(record.xml())
                        _eventid = data_dict["EventID"]
                        if _original_dict.get("Event", None):
                            _key = list(_original_dict["Event"].keys())[-1]
                            if _original_dict["Event"].get(_key, None):
                                if "Data" in list(_original_dict["Event"][_key].keys()):
                                    if _original_dict["Event"][_key].get("Data", None):
                                        for _d in _original_dict["Event"][_key]["Data"]:
                                            if type(_d) is dict and _d.get(
                                                "@Name", False
                                            ):
                                                data_dict[_d.get("@Name")] = _d.get(
                                                    "#text", ""
                                                )
                                else:
                                    for _k, _v in _original_dict["Event"][_key].items():
                                        data_dict[_k] = _v
                        if self._mapping.get(
                            re.sub(r"%\d+", "-", self._evtx_file.stem), None
                        ):
                            if self._mapping[
                                re.sub(r"%\d+", "-", self._evtx_file.stem)
                            ].get(_eventid, None):
                                data_dict["Description"] = self._mapping[
                                    re.sub(r"%\d+", "-", self._evtx_file.stem)
                                ][_eventid]
                        data_dict.update(extrafields)
                        self.send_to_elk(data=data_dict)
                        _events.append(data_dict)
                        json.dump(data_dict, _jsonl_output)
                        _jsonl_output.write("\n")
                        _index += 1
                    except Exception as ex:
                        self.logger.error(f"Error in record -- {ex}")
            _result["nb_events_sent"] = _index
        except Exception as ex:
            self.logger.error(f"err-- {self._evtx_file.stem}")
            self.logger.error(f"err-- {ex}")
        finally:
            if self._socket is not None:
                self._socket.close()
            if _jsonl_output:
                _jsonl_output.close
            return _result
