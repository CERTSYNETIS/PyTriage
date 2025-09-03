import pypff
import re
import json
import os
import hashlib
from pathlib import Path
from logging import Logger
from datetime import datetime
from ..triageutils import send_data_to_elk, delete_file, generate_analytics, file_exists


class PSTParser:
    """
    Class to handle PST file format
    """

    def __init__(
        self,
        pstfile: Path,
        output_dir: Path,
        logstash_url: str,
        port: int,
        logger: Logger,
        analytics_port: int = 5050,
        extrafields: dict = {},
        extract_attachments: bool = False,
        is_logstash_active: bool = False,
    ):
        self.extract_attachments = extract_attachments
        self.logstash_url = logstash_url
        self.port = port
        self.logger = logger
        self.extrafields = extrafields
        self.analytics_port = analytics_port
        self.pstfile = pstfile
        self.output_dir = output_dir
        self.is_logstash_active = is_logstash_active
        self._analytics = generate_analytics()
        self._analytics["log"]["file"]["attachments"] = 0

    def save_attachment(self, data, path: str = "", name: str = "") -> None:
        try:
            with open(os.path.join(path, name), "wb+") as out:
                out.write(data)
                self.logger.debug(
                    f"[PST][save_attachement] Successfully saved {str(name)}"
                )
        except Exception as e:
            self.logger.error(
                f"[PST][save_attachement] Failure on writing attachment {str(e)}"
            )

    def process_folders(self, pff_folder) -> list:
        try:
            folder_name = pff_folder.name if pff_folder.name else "N/A"
            self.logger.info(
                f"[process_folders] Folder: {folder_name} | Sub Folders: {pff_folder.number_of_sub_folders} | Sub Msg: {pff_folder.number_of_sub_messages}"
            )
            # Process messages within a folder
            data_list = list()
            _res = dict()
            _res["folder"] = folder_name
            _res["subfolder"] = pff_folder.number_of_sub_folders
            _res["submessages"] = pff_folder.number_of_sub_messages
            _tmp_msgs = list()
            for msg in pff_folder.sub_messages:
                try:
                    _parsed_msg = self.process_message(msg)
                    try:
                        if self.is_logstash_active:
                            _res["message"] = _parsed_msg
                            self.send_to_elk(json_data=_res, extrafields=self.extrafields)
                            self._analytics["log"]["file"]["eventsent"] += 1
                            del _res["message"]
                    except Exception as ex:
                        self.logger.error(f"[process_message] send to elk: {ex}")
                    _tmp_msgs.append(_parsed_msg)
                except Exception as ex:
                    self.logger.error(f"[process_folder] msg: {ex}")
            #Do not send big array to ELK but keep it in jsonl result file
            _res["messages"] = _tmp_msgs
            try:
                # Process folders within a folder
                for folder in pff_folder.sub_folders:
                    data_list.extend(self.process_folders(folder))
            except Exception as e:
                self.logger.error(
                    f"[process_folders] Failure on iterating over folder {e}"
                )
            data_list.append(_res)
            return data_list
        except Exception as e:
            self.logger.error(f"[process_folders] {e}")
            return list()

    def _fingerprints(self, blob) -> dict:
        _metas = dict()
        _metas["sha-1"] = ""
        _metas["md5"] = ""
        _metas["sha-256"] = ""
        if not isinstance(blob, bytes):
            self.logger.error(
                f"[fingerprints] Error during hashing : input must be a bytes object"
            )
            return _metas
        try:
            md5 = hashlib.md5()
            sha1 = hashlib.sha1()
            sha256 = hashlib.sha256()
            md5.update(blob)
            sha1.update(blob)
            sha256.update(blob)
            _metas["md5"] = md5.hexdigest()
            _metas["sha-1"] = sha1.hexdigest()
            _metas["sha-256"] = sha256.hexdigest()
            return _metas
        except Exception as e:
            self.logger.error(f"[fingerprints] {str(e)}")
            return _metas

    def process_body(self, body=b"", charset=None) -> str:
        try:
            encoding = None
            if body:
                try:
                    encoding = json.detect_encoding(bytes(body))
                    return body.decode(encoding)
                except Exception as er:
                    encoding = "utf-8"
                    self.logger.error(f"[process_body] Encoding: {str(er)}")
                    return body.decode(encoding)
            else:
                return ""
        except Exception as e:
            self.logger.error(f"[process_body] {e}")
            return ""

    def process_message(self, msg) -> dict:
        try:
            # Extract attributes
            _attribs = [
                "conversation_topic",
                "number_of_sub_items",
                "identifier",
                "number_of_entries",
                "number_of_record_sets",
                "sender_name",
                "subject",
                "transport_headers",
            ]
            _time_attribs = [
                "creation_time",
                "delivery_time",
                "client_submit_time",
                "date",
                "modification_time",
            ]
            self._analytics["log"]["file"]["eventcount"] += 1
            data_dict = dict()
            data_dict["subitems"] = list()
            ## ==== step 1 : get message attributes
            try:
                if getattr(msg, "number_of_sub_items", 0):
                    for i in msg.sub_items:
                        data_dict["subitems"].append(self.process_message(i))
            except Exception as sub_ex:
                self.logger.error(f"subitems: {sub_ex}")

            # get timestamp attributes
            for attrib in _time_attribs:
                try:
                    data_dict[attrib] = datetime.strptime(
                        date_string=str(getattr(msg, attrib, "")),
                        format="%d/%m/%Y %H:%M:%S"
                    )
                except Exception as e:
                    data_dict[attrib] = str(getattr(msg, attrib, "N/A"))

            # get other attributes
            for attrib in _attribs:
                try:
                    data_dict[attrib] = getattr(msg, attrib, "N/A")
                except Exception as e:
                    self.logger.error(f"[process_message] attribute : {e}")

            ## ==== step 2 : get message body
            body = msg.get_plain_text_body()
            data_dict["body"] = self.process_body(body)
            ## ==== step 3 : get message headers
            if msg.transport_headers:
                data_dict["headers"] = self.process_headers(msg.transport_headers)
            if msg.conversation_topic:
                data_dict["topic"] = msg.get_conversation_topic()
            _temp = self.process_attachments(msg)
            data_dict["attachments"] = _temp
            data_dict["numberofattachments"] = len(_temp)
            self._analytics["log"]["file"]["attachments"] += len(_temp)
            return data_dict
        except Exception as e:
            self.logger.error(f"[process_message] {e}")
            return dict()

    def process_attachments(self, msg) -> list:
        _attachments = list()
        try:
            for _i in msg.attachments:
                try:
                    attrs = dict()
                    attrs["filename"] = _i.name if _i.name else "unknown.data"
                    attrs["size"] = _i.size if _i.size else 0
                    attrs["identifier"] = _i.identifier if _i.identifier else "N/A"
                    content = _i.read_buffer(_i.size)
                    attrs["fingerprints"] = self._fingerprints(blob=content)
                    _attachments.append(attrs)
                    if self.extract_attachments and attrs.get("size", 0):
                        self.export_content(
                            content=content,
                            output=self.output_dir,
                            filename=f'{attrs["fingerprints"]["sha-1"]}_{attrs["filename"]}',
                        )
                except Exception as ex:
                    self.logger.error(
                        f"[process_attachments] Error reading attachments content : {ex}"
                    )
            return _attachments
        except Exception as error:
            self.logger.error(f"[process_attachments] {error}")
            return list()

    def export_content(
        self,
        content,
        output: Path,
        filename: str,
    ):
        """
        Takes :
            msg: object
            output: str
            content_data: str or binary object
        """
        try:
            self.logger.info(f"[export_content] Saving to {output / Path(filename)}")
            if isinstance(content, bytes):
                open(output / Path(filename), "wb").write(content)
            else:
                open(output / Path(filename), "w").write(content)
        except Exception as e:
            self.logger.error(f"[export_content] {e}")

    def process_headers(self, header) -> dict:
        try:
            # Read and process header information
            # Improvement : filter on ECS field to add them to root document
            key_pattern = re.compile("^([A-Za-z0-9\-]+:)(.*)$")
            header_data = dict()
            for line in header.split("\r\n"):
                if not len(line):
                    continue
                reg_result = key_pattern.match(line)
                if reg_result:
                    key = reg_result.group(1).strip(":").strip()
                    value = reg_result.group(2).strip()
                else:
                    value = line

                if key.lower() in header_data:
                    if isinstance(header_data[key.lower()], list):
                        header_data[key.lower()].append(value)
                    else:
                        header_data[key.lower()] = [header_data[key.lower()], value]
                else:
                    header_data[key.lower()] = value
            return header_data
        except Exception as e:
            self.logger.error(f"[process_headers] {e}")
            return dict()

    def analytics(self):
        try:
            ip = self.logstash_url
            if ip.startswith("http"):
                ip = self.logstash_url.split("//")[1]
            send_data_to_elk(
                data=self._analytics,
                ip=ip,
                port=self.analytics_port,
                logger=self.logger,
                extrafields=self.extrafields,
            )
        except Exception as e:
            self.logger.error(f"[PST][send_analytics_to_elk] {str(e)}")
            raise e

    def run(self):
        try:
            pff_obj = pypff.file()
            pff_obj.open(str(self.pstfile))
            parsed_data = self.process_folders(pff_obj.root_folder)
            self._analytics["log"]["file"]["path"] = str(self.pstfile)
            self._analytics["log"]["file"]["size"] = self.pstfile.stat().st_size
            self._analytics["log"]["file"]["eventcount"] = len(parsed_data)
            self.write_json(
                content=parsed_data,
                output_file=self.output_dir / Path(f"{self.pstfile.stem}.json"),
            )
            pff_obj.close()
        except Exception as e:
            self.logger.error(f"[run] {str(e)}")

    def send_to_elk(self, json_data: dict, extrafields: dict = {}):
        try:
            ip = self.logstash_url
            if ip.startswith("http"):
                ip = self.logstash_url.split("//")[1]
            send_data_to_elk(
                data=json_data,
                ip=ip,
                port=self.port,
                logger=self.logger,
                extrafields=extrafields,
            )
        except Exception as e:
            self.logger.error(f"[send_to_elk] {e}")

    def write_json(self, content: list, output_file: Path):
        try:
            if file_exists(file=output_file, logger=self.logger):
                delete_file(src=output_file, logger=self.logger)
            self.logger.info(f"[write_json] {output_file}")
            with open(output_file, "w") as outfile:
                json.dump(content, outfile, indent=4)
        except Exception as ex:
            self.logger.error(f"[write_json] {ex}")
