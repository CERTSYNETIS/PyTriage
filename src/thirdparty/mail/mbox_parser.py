from __future__ import print_function
import mailbox
import json
import base64
import hashlib
from logging import Logger
import bs4
from pathlib import Path
import re
from ..triageutils import send_data_to_elk, delete_file, generate_analytics


class MBOXParser:
    """
    Class to handle MBOX file format
    """

    def __init__(
        self,
        mbox_path: Path,
        output_dir: Path,
        logstash_url: str,
        port: int,
        extrafields: dict,
        logger: Logger,
        analytics_port: int = 5050,
        extract_attachments: bool = False,
        is_logstash_active: bool = False,
    ):
        self.extract_attachments = extract_attachments
        self.logstash_url = logstash_url
        self.port = port
        self.logger = logger
        self.extrafields = extrafields
        self.analytics_port = analytics_port
        self.mbox_path = mbox_path
        self.output_dir = output_dir
        self.is_logstash_active = is_logstash_active
        self._analytics = generate_analytics()

    def send_to_elk(self, json_data: list, extrafields: dict = {}):
        """Fonction qui envoie les résultats d'un array vers ELK"""
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

    def custom_reader(self, data_stream):
        data = data_stream.read()
        try:
            content = data.decode("utf-8", errors="ignore")
        except (UnicodeDecodeError, UnicodeEncodeError) as e1:
            try:
                content = data.decode("ascii", errors="ignore")
            except UnicodeDecodeError as e2:
                try:
                    content = data.decode("latin-1", errors="ignore")
                except UnicodeDecodeError as e3:
                    content = data.decode("cp1252", errors="replace")
        return mailbox.mboxMessage(content)

    def get_filename(self, msg):
        if "name=" in msg.get("Content-Disposition", "N/A"):
            fname_data = msg["Content-Disposition"].replace("\r\n", " ")
            fname = [x for x in fname_data.split("; ") if "name=" in x]
            file_name = fname[0].split("=", 1)[-1]
        elif "name=" in msg.get("Content-Type", "N/A"):
            fname_data = msg["Content-Type"].replace("\r\n", " ")
            fname = [x for x in fname_data.split("; ") if "name=" in x]
            file_name = fname[0].split("=", 1)[-1]
        else:
            file_name = ""
        fchars = [x for x in file_name if x.isalnum() or x.isspace() or x == "."]
        return "".join(fchars)

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

    def get_html_text(self, html) -> str:
        try:
            return bs4.BeautifulSoup(html, "lxml").body.get_text(" ", strip=True)
        except AttributeError:  # message contents empty
            self.logger.error(f"[get_html_text] Message contents empty")
            return ""

    def _read_email_text(self, msg) -> str:
        content_type = "NA" if isinstance(msg, str) else msg.get_content_type()
        encoding = (
            "NA" if isinstance(msg, str) else msg.get("Content-Transfer-Encoding", "NA")
        )
        if "text/html" in content_type and "base64" not in encoding:
            msg_text = self.get_html_text(msg.get_payload())
        elif content_type == "NA":
            msg_text = self.get_html_text(msg)
        else:
            msg_text = ""
        return msg_text

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

    def parse_attachments(self, msg, extract: bool = False):
        try:
            pyld = msg.get_payload()
            export_path = list()
            _res = {"body": "", "filename": "", "fingerprints": {}}
            if msg.is_multipart():
                for entry in pyld:
                    export_path.extend(
                        self.parse_attachments(msg=entry, extract=extract)
                    )
            else:
                _res["filename"] = self.get_filename(msg)
                content_type = msg.get_content_type()
                if "application/" in content_type.lower():
                    content = base64.b64decode(pyld)
                    self._analytics["log"]["file"]["attachments"] += 1
                    _res["fingerprints"] = self._fingerprints(blob=content)
                elif "image/" in content_type.lower():
                    content = base64.b64decode(pyld)
                    self._analytics["log"]["file"]["attachments"] += 1
                    _res["fingerprints"] = self._fingerprints(blob=content)
                elif "video/" in content_type.lower():
                    content = base64.b64decode(pyld)
                    self._analytics["log"]["file"]["attachments"] += 1
                    _res["fingerprints"] = self._fingerprints(blob=content)
                elif "audio/" in content_type.lower():
                    content = base64.b64decode(pyld)
                    self._analytics["log"]["file"]["attachments"] += 1
                    _res["fingerprints"] = self._fingerprints(blob=content)
                elif "text/csv" in content_type.lower():
                    content = base64.b64decode(pyld)
                    self._analytics["log"]["file"]["attachments"] += 1
                    _res["fingerprints"] = self._fingerprints(blob=content)
                elif "info/" in content_type.lower():
                    _res["body"] = pyld
                    extract = False
                elif (
                    "text/calendar" in content_type.lower()
                    or "text/rtf" in content_type.lower()
                ):
                    self._analytics["log"]["file"]["attachments"] += 1
                    _res["fingerprints"] = self._fingerprints(blob=content)

                elif "text/plain" in content_type.lower():
                    _res["body"] = msg.get_payload()
                    extract = False
                elif "text/html" in content_type.lower():
                    _res["body"] = self._read_email_text(msg=msg)
                    extract = False
                else:
                    if "name=" in msg.get("Content-Disposition", "N/A"):
                        content = base64.b64decode(msg.get_payload())
                        _res["fingerprints"] = self._fingerprints(blob=content)
                    elif "name=" in msg.get("Content-Type", "N/A"):
                        content = base64.b64decode(msg.get_payload())
                        _res["fingerprints"] = self._fingerprints(blob=content)

                if extract:
                    self.export_content(
                        content=content,
                        output=self.output_dir,
                        filename=f'{_res["fingerprints"]["sha-1"]}_{_res["filename"]}',
                    )
                export_path.append(_res)
        except Exception as ex:
            self.logger.error(f"[parse_attachments] {ex}")
        return export_path

    def run(self):
        try:
            # Read in the MBOX File
            email = dict()
            email["path"] = str(self.mbox_path)
            email["attachments"] = list()
            email["headers"] = dict()
            mbox = mailbox.mbox(path=self.mbox_path, factory=self.custom_reader)
            self.logger.info(f"[run] Number of messages to parse {len(mbox)}")
            self._analytics["log"]["file"]["eventcount"] = len(mbox)
            self._analytics["log"]["file"]["path"] = str(self.mbox_path)
            self._analytics["log"]["file"]["size"] = self.mbox_path.stat().st_size
            for message in mbox:
                header_data = dict(message._headers)
                for hdr in header_data:
                    email["headers"][hdr] = header_data.get(hdr, "N/A")
                try:
                    if len(message.get_payload()):
                        email["attachments"].append(
                            self.parse_attachments(
                                msg=message,
                                extract=self.extract_attachments,
                            )
                        )
                    else:
                        self.logger.info(f"[run] No payload detected in this message")
                except Exception as e:
                    self.logger.error(f"[run] Error reading payload {str(e)}")
                if self.is_logstash_active:
                    try:
                        self.send_to_elk(json_data=email, extrafields=self.extrafields)
                        self._analytics["log"]["file"]["eventsent"] += 1
                    except Exception as ex:
                        pass
            self.write_json(
                content=email,
                output_file=self.output_dir / Path(f"{self.mbox_path.stem}.json"),
            )
        except Exception as e:
            self.logger.error(f"[run] {str(e)}")
            raise e

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
            self.logger.error(f"[send_analytics_to_elk] {str(e)}")
            raise e

    def write_json(self, content: dict, output_file: Path):
        try:
            delete_file(src=output_file, logger=self.logger)
            with open(output_file, "w") as outfile:
                json.dump(content, outfile, indent=4)
        except Exception as ex:
            self.logger.error(f"[write_json] {ex}")
