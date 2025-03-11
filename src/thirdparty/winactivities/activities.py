import ujson
import binascii
from collections import OrderedDict
from .helpers import DbHandler, datetime_decode_1970_str

ACTIVITIES_SCHEMA = {
    "tables": [
        "Activity",
        "Activity_PackageId",
        "ActivityAssetCache",
        "Asset",
        "ActivityOperation",
        "AppSettings",
        "ManualSequence",
        "DataEncryptionKeys",
        "Metadata",
    ],
    "views": ["SmartLookup"],
}


class ActivitiesDb(object):
    def __init__(self, source):
        self._source = source
        self.db_handler = DbHandler(database=self._source)

    def iter_records(self):
        for table_name in ACTIVITIES_SCHEMA["tables"]:
            try:
                query_str = """
                    SELECT rowid, *
                    FROM {}
                """.format(
                    table_name
                )
                for row in self.db_handler.iter_rows(query_str):
                    record = self.get_record(table_name, row)
                    setattr(record, "_table", table_name)
                    yield record
            except Exception as ex:
                print(f"[Error] {ex}")

    def get_record(self, collection_name, row):
        if collection_name == "Activity":
            return ActivityRecord(row)
        elif collection_name == "Activity_PackageId":
            return PackageIdRecord(row)
        elif collection_name == "ActivityOperation":
            return ActivityOperationRecord(row)
        elif collection_name == "Asset":
            return AssetRecord(row)
        elif collection_name == "DataEncryptionKeys":
            return DataEncryptionKeysRecord(row)
        elif collection_name == "AppSettings":
            return AppSettingsRecord(row)
        else:
            return GenericRecord(row)

    def get_activity_sequence(self):
        sequence_query_str = """
        SELECT
        ManualSequence.Value
        FROM
        ManualSequence
        WHERE "Key" LIKE "Activity"
        """
        connection = self.db_handler.get_connection()
        cursor = connection.cursor()
        cursor.execute(sequence_query_str)
        sequence = cursor.fetchone()
        return sequence[0]

    def iter_activities(self, sequence=0):
        query_str = """
            SELECT rowid, *
            FROM Activity
            WHERE ETag > {}
            ORDER BY ETag DESC
        """.format(
            sequence
        )
        for row in self.db_handler.iter_rows(query_str):
            yield ActivityRecord(row)


class GenericRecord(dict):
    def __init__(self, row):
        self.update(row)

    def as_ordered_dict(self):
        """Reformat record"""
        record = OrderedDict([])
        record.update(self)
        return record


class AssetRecord(dict):
    def __init__(self, row):
        self.update(row)

    def as_ordered_dict(self):
        """Reformat record"""
        record = OrderedDict(
            [
                ("Id", binascii.b2a_hex(self["Id"])),
                ("AssetPayload", self["AssetPayload"]),
                ("Status", self["Status"]),
                ("LastRefreshTime", datetime_decode_1970_str(self["LastRefreshTime"])),
            ]
        )

        return record


class DataEncryptionKeysRecord(dict):
    def __init__(self, row):
        self.update(row)

    def as_ordered_dict(self):
        """Reformat record"""
        record = OrderedDict(
            [
                ("KeyVersion", self["KeyVersion"]),
                ("KeyValue", self["KeyValue"]),
                (
                    "CreatedInCloudTime",
                    datetime_decode_1970_str(self["CreatedInCloudTime"]),
                ),
            ]
        )

        return record


class AppSettingsRecord(dict):
    def __init__(self, row):
        self.update(row)

    def as_ordered_dict(self):
        """Reformat record"""
        record = OrderedDict(
            [
                ("AppId", self["AppId"]),
                ("SettingsPropertyBag", self["SettingsPropertyBag"]),
                ("AppTitle", self["AppTitle"]),
                ("Logo4141", self["Logo4141"]),
            ]
        )

        return record


class ActivityOperationRecord(dict):
    def __init__(self, row):
        self.update(row)

    def as_ordered_dict(self):
        """Reformat record"""
        record = OrderedDict(
            [
                ("OperationOrder", self["OperationOrder"]),
                ("Id", binascii.b2a_hex(self["Id"])),
                ("OperationType", self["OperationType"]),
                ("AppId", ujson.loads(self["AppId"])),
                ("PackageIdHash", self["PackageIdHash"]),
                ("AppActivityId", self["AppActivityId"]),
                ("ActivityType", self["ActivityType"]),
                ("ParentActivityId", self["ParentActivityId"]),
                ("Tag", self["Tag"]),
                ("Group", self["Group"]),
                ("MatchId", self["MatchId"]),
                (
                    "LastModifiedTime",
                    datetime_decode_1970_str(self["LastModifiedTime"]),
                ),
                ("ExpirationTime", datetime_decode_1970_str(self["ExpirationTime"])),
                ("Payload", ujson.loads(self["Payload"])),
                ("Priority", self["Priority"]),
                ("CreatedTime", datetime_decode_1970_str(self["CreatedTime"])),
                ("Attachments", self["Attachments"]),
                ("PlatformDeviceId", self["PlatformDeviceId"]),
                ("CreatedInCloud", self["CreatedInCloud"]),
                ("StartTime", datetime_decode_1970_str(self["StartTime"])),
                ("EndTime", datetime_decode_1970_str(self["EndTime"])),
                ("LastModifiedOnClient", self["LastModifiedOnClient"]),
                ("CorrelationVector", self["CorrelationVector"]),
                ("GroupAppActivityId", self["GroupAppActivityId"]),
                ("ClipboardPayload", self["ClipboardPayload"]),
                ("EnterpriseId", self["EnterpriseId"]),
                ("OriginalPayload", self["OriginalPayload"]),
                ("OriginalLastModifiedOnClient", self["OriginalLastModifiedOnClient"]),
                ("ETag", self["ETag"]),
            ]
        )

        return record


class PackageIdRecord(dict):
    def __init__(self, row):
        self.update(row)

    def as_ordered_dict(self):
        """Reformat record"""
        record = OrderedDict(
            [
                ("_rowid", self["rowid"]),
                ("ActivityId", binascii.b2a_hex(self["ActivityId"])),
                ("Platform", self["Platform"]),
                ("PackageName", self["PackageName"]),
                ("ExpirationTime", datetime_decode_1970_str(self["ExpirationTime"])),
            ]
        )

        return record


class ActivityRecord(dict):
    def __init__(self, row):
        self.update(row)

    def as_ordered_dict(self):
        """Reformat record"""
        try:
            _payload = ujson.loads(self["Payload"])
        except Exception as ex:
            _payload = dict()

        record = OrderedDict(
            [
                ("_rowid", self["rowid"]),
                ("Id", binascii.b2a_hex(self["Id"])),
                ("AppId", ujson.loads(self["AppId"])),
                ("PackageIdHash", self["PackageIdHash"]),
                ("AppActivityId", self["AppActivityId"]),
                ("ActivityType", self["ActivityType"]),
                ("ActivityStatus", self["ActivityStatus"]),
                ("ParentActivityId", binascii.b2a_hex(self["ParentActivityId"])),
                ("Tag", self["Tag"]),
                ("Group", self["Group"]),
                ("MatchId", self["MatchId"]),
                (
                    "LastModifiedTime",
                    datetime_decode_1970_str(self["LastModifiedTime"]),
                ),
                ("ExpirationTime", datetime_decode_1970_str(self["ExpirationTime"])),
                ("Payload", _payload),
                ("Priority", self["Priority"]),
                ("IsLocalOnly", self["IsLocalOnly"]),
                ("PlatformDeviceId", self["PlatformDeviceId"]),
                ("CreatedInCloud", self["CreatedInCloud"]),
                ("StartTime", datetime_decode_1970_str(self["StartTime"])),
                ("EndTime", datetime_decode_1970_str(self["EndTime"])),
                (
                    "LastModifiedOnClient",
                    datetime_decode_1970_str(self["LastModifiedOnClient"]),
                ),
                ("GroupAppActivityId", self["GroupAppActivityId"]),
                ("ClipboardPayload", self["ClipboardPayload"]),
                ("EnterpriseId", self["EnterpriseId"]),
                ("OriginalPayload", self["OriginalPayload"]),
                (
                    "OriginalLastModifiedOnClient",
                    datetime_decode_1970_str(self["OriginalLastModifiedOnClient"]),
                ),
                ("ETag", self["ETag"]),
            ]
        )

        return record

    def to_csv(self):
        row = list()
        for _v in self.values():
            row.append(str(_v))
        return row
