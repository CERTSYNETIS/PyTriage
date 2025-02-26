import struct
import collections
from pathlib import Path
from datetime import datetime


class ParseUSNJRNL:
    """
    Class to Parse $UsnJrnl file
    """

    def __init__(
        self,
        usn_file: Path,
        result_csv_file: Path,
        result_body_file: Path = None,
        logger=None,
    ) -> None:
        self.usn_file = usn_file
        self.result_csv_file = result_csv_file
        self.result_body_file = result_body_file
        self.logger = logger

        self.reasons = collections.OrderedDict()
        self.reasons[0x1] = "DATA_OVERWRITE"
        self.reasons[0x2] = "DATA_EXTEND"
        self.reasons[0x4] = "DATA_TRUNCATION"
        self.reasons[0x10] = "NAMED_DATA_OVERWRITE"
        self.reasons[0x20] = "NAMED_DATA_EXTEND"
        self.reasons[0x40] = "NAMED_DATA_TRUNCATION"
        self.reasons[0x100] = "FILE_CREATE"
        self.reasons[0x200] = "FILE_DELETE"
        self.reasons[0x400] = "EA_CHANGE"
        self.reasons[0x800] = "SECURITY_CHANGE"
        self.reasons[0x1000] = "RENAME_OLD_NAME"
        self.reasons[0x2000] = "RENAME_NEW_NAME"
        self.reasons[0x4000] = "INDEXABLE_CHANGE"
        self.reasons[0x8000] = "BASIC_INFO_CHANGE"
        self.reasons[0x10000] = "HARD_LINK_CHANGE"
        self.reasons[0x20000] = "COMPRESSION_CHANGE"
        self.reasons[0x40000] = "ENCRYPTION_CHANGE"
        self.reasons[0x80000] = "OBJECT_ID_CHANGE"
        self.reasons[0x100000] = "REPARSE_POINT_CHANGE"
        self.reasons[0x200000] = "STREAM_CHANGE"
        self.reasons[0x80000000] = "CLOSE"

        self.attributes = collections.OrderedDict()
        self.attributes[0x1] = "READONLY"
        self.attributes[0x2] = "HIDDEN"
        self.attributes[0x4] = "SYSTEM"
        self.attributes[0x10] = "DIRECTORY"
        self.attributes[0x20] = "ARCHIVE"
        self.attributes[0x40] = "DEVICE"
        self.attributes[0x80] = "NORMAL"
        self.attributes[0x100] = "TEMPORARY"
        self.attributes[0x200] = "SPARSE_FILE"
        self.attributes[0x400] = "REPARSE_POINT"
        self.attributes[0x800] = "COMPRESSED"
        self.attributes[0x1000] = "OFFLINE"
        self.attributes[0x2000] = "NOT_CONTENT_INDEXED"
        self.attributes[0x4000] = "ENCRYPTED"
        self.attributes[0x8000] = "INTEGRITY_STREAM"
        self.attributes[0x10000] = "VIRTUAL"
        self.attributes[0x20000] = "NO_SCRUB_DATA"

        self.sourceInfo = collections.OrderedDict()
        self.sourceInfo[0x1] = "DATA_MANAGEMENT"
        self.sourceInfo[0x2] = "AUXILIARY_DATA"
        self.sourceInfo[0x4] = "REPLICATION_MANAGEMENT"

    def parseUsn(self, infile, usn) -> dict:
        recordProperties = [
            "majorVersion",
            "minorVersion",
            "fileReferenceNumber",
            "parentFileReferenceNumber",
            "usn",
            "timestamp",
            "reason",
            "sourceInfo",
            "securityId",
            "fileAttributes",
            "filenameLength",
            "filenameOffset",
        ]
        recordDict = dict(zip(recordProperties, usn))
        recordDict["filename"] = self.filenameHandler(infile, recordDict)
        recordDict["reason"] = self.convertAttributes(
            self.reasons, recordDict["reason"]
        )
        recordDict["fileAttributes"] = self.convertAttributes(
            self.attributes, recordDict["fileAttributes"]
        )
        recordDict["humanTimestamp"] = self.filetimeToHumanReadable(
            recordDict["timestamp"]
        )
        recordDict["epochTimestamp"] = self.filetimeToEpoch(recordDict["timestamp"])
        recordDict["timestamp"] = self.filetimeToEpoch(recordDict["timestamp"])
        (
            recordDict["mftSeqNumber"],
            recordDict["mftEntryNumber"],
        ) = self.convertFileReference(recordDict["fileReferenceNumber"])
        (
            recordDict["pMftSeqNumber"],
            recordDict["pMftEntryNumber"],
        ) = self.convertFileReference(recordDict["parentFileReferenceNumber"])
        return recordDict

    def findFirstRecord(self, infile):
        while True:
            data = infile.read(65536).lstrip(b"\x00")
            if data:
                return infile.tell() - len(data)
            else:
                return 0

    def findNextRecord(self, infile, journalSize):
        while True:
            try:
                recordLength = struct.unpack_from("<I", infile.read(4))[0]
                if recordLength:
                    infile.seek(-4, 1)
                    return infile.tell() + recordLength
            except struct.error:
                if infile.tell() >= journalSize:
                    return 0

    def filetimeToHumanReadable(self, filetime) -> str:
        try:
            return str(datetime.fromtimestamp(float(filetime) * 1e-7 - 11644473600))
        except ValueError:
            return "error"

    def filetimeToEpoch(self, filetime) -> int:
        return int(filetime / 10000000 - 11644473600)

    def convertFileReference(self, buf):
        sequenceNumber = (buf >> 48) & 0xFFFF
        entryNumber = buf & 0xFFFFFFFFFFFF
        return sequenceNumber, entryNumber

    def filenameHandler(self, infile, recordDict):
        try:
            filename = struct.unpack_from(
                "<{}s".format(recordDict["filenameLength"]),
                infile.read(recordDict["filenameLength"]),
            )[0]
            return filename.decode("utf16")
        except UnicodeDecodeError:
            return ""

    def convertAttributes(self, attributeType, data):
        attributeList = [attributeType[i] for i in attributeType if i & data]
        return " ".join(attributeList)

    def analyze(self):
        try:
            self.logger.info(f"[ParseUSNJRNL] Start parsing -- {self.usn_file}")
            _csv_file = open(self.result_csv_file, "wb")
            if _csv_file is None:
                raise Exception("[analyze] error in csvfile creation")
            _body_file = None
            if self.result_body_file:
                _body_file = open(self.result_body_file, "wb")
            journalSize = self.usn_file.stat().st_size
            with open(self.usn_file, "rb") as i:
                i.seek(self.findFirstRecord(i))
                _csv_file.write(
                    "timestamp,filename,fileattr,reason\n".encode(
                        "utf-8", errors="backslashreplace"
                    )
                )
                while True:
                    nextRecord = self.findNextRecord(i, journalSize)
                    if nextRecord == 0:
                        break
                    recordLength = struct.unpack_from("<I", i.read(4))[0]
                    recordData = struct.unpack_from("<2H4Q4I2H", i.read(56))
                    try:
                        u = self.parseUsn(i, recordData)
                        _csv_line = f'{u["humanTimestamp"]},{u["filename"]},{u["fileAttributes"]},{u["reason"]}\n'
                        _csv_file.write(
                            _csv_line.encode("utf8", errors="backslashreplace")
                        )
                        _body_line = f'0|{u["filename"]} (USN: {u["reason"]})|{u["mftEntryNumber"]}-{u["mftSeqNumber"]}|0|0|0|0|{u["epochTimestamp"]}|{u["epochTimestamp"]}|{u["epochTimestamp"]}|{u["epochTimestamp"]}\n'
                        if _body_file:
                            _body_file.write(
                                _body_line.encode("utf8", errors="backslashreplace")
                            )
                    except Exception as e:
                        self.logger.error(f"[ParseUSNJRNL] {e}")
                    finally:
                        i.seek(nextRecord)
            self.logger.info("[ParseUSNJRNL] Results files created")
        except Exception as ex:
            self.logger.error(f"[ParseUSNJRNL] main -- {ex}")
        finally:
            if _csv_file:
                _csv_file.close()
            if _body_file:
                _body_file.close()
            self.logger.info("[ParseUSNJRNL] Stop parsing")
