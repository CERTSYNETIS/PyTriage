import os
import ujson
import shutil
import pytsk3
import logging
import tempfile
import datetime
from .helpers import CustomStringFormatter
from .activities import ActivitiesDb


class SetMeta(object):
    def __init__(self, username, cdp_location):
        self.username = username
        self.cdp_location = cdp_location


class ExtractionSet(object):
    def __init__(self, temp_base, username, cdp_location):
        temp_location = "{}-{}".format(username, cdp_location)
        temp_location = os.path.join(temp_base, temp_location)
        logging.info("Temp location: {}".format(temp_location))

        self.set_metadata = SetMeta(username, cdp_location)
        self.set_extract_location = temp_location

        self.files = []
        if not os.path.isdir(self.set_extract_location):
            os.mkdir(self.set_extract_location)

    def extract_file(self, tsk_file, source_path):
        if not tsk_file.info.meta.size > 0:
            return

        file_name = tsk_file.info.name.name.decode("utf-8")
        temp_file_name = os.path.join(self.set_extract_location, file_name)
        logging.info("Extracting: {} -> {}".format(source_path, temp_file_name))

        with open(temp_file_name, "wb") as fh:
            data = tsk_file.read_random(0, tsk_file.info.meta.size)
            fh.write(data)

        self.files.append(temp_file_name)

    def get_activities_location(self):
        for location in self.files:
            if location.endswith("ActivitiesCache.db"):
                return location


class TempFileManager(object):
    def __init__(self, temp_location=None, cleanup=False):
        self.temp_location = temp_location
        self.cleanup = cleanup
        self.extraction_sets = []

        if not self.temp_location:
            temp_base = tempfile.gettempdir()
            loc_folder = "win-activities-" + datetime.datetime.now().strftime(
                "%Y%m%d%H%M%S"
            )
            temp_loc = os.path.join(temp_base, loc_folder)
            self.temp_location = temp_loc

    def get_extraction_set(self, username, cdp_location):
        extraction_set = ExtractionSet(self.temp_location, username, cdp_location)
        self.extraction_sets.append(extraction_set)
        return extraction_set

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.cleanup:
            shutil.rmtree(self.temp_location)


class VolumeProcessor(object):
    """A class to process the logical volume."""

    def __init__(
        self,
        file_io,
        description="",
        temp_location=None,
        cleanup=False,
        output_template=False,
        dump_db=False,
    ):
        """Create LogicalEnumerator

        Params:
            file_io (FileIO): I file like object representing a volume.
            description (unicode): description of the volume
            temp_location (unicode): The location to extract files to
            cleanup (bool): Remove the temp folder after processesing
            output_template (unicode): The output template.
            dump_db (bool): True = Dump all database tables.
        """
        self.file_io = file_io
        self.description = description
        self.tsk_fs = pytsk3.FS_Info(self.file_io)
        self.temp_manager = TempFileManager(
            temp_location=temp_location, cleanup=cleanup
        )
        self.output_template = output_template
        self.dump_db = dump_db

    def process(self):
        """Extract and process files from a logical volume."""
        user_name_list = self._username_list()
        extraction_mapping = {}
        for username in user_name_list:
            base_location = (
                "/Users/{username}/AppData/Local/ConnectedDevicesPlatform/".format(
                    username=username
                )
            )
            settings = self._get_cpd_global_settings(
                base_location + "CDPGlobalSettings.cdp"
            )
            if not settings:
                continue

            extraction_mapping[username] = {}
            for info in settings["ActivityStoreInfo"]:
                if not info["stableUserId"] in extraction_mapping[username]:
                    extraction_mapping[username][info["stableUserId"]] = []

                db_location = base_location + "{id}/".format(id=info["stableUserId"])
                activities_db = db_location + "ActivitiesCache.db"
                activities_wal = db_location + "ActivitiesCache.db-wal"
                activities_shm = db_location + "ActivitiesCache.db-shm"

                extraction_mapping[username][info["stableUserId"]].append(activities_db)
                extraction_mapping[username][info["stableUserId"]].append(
                    activities_wal
                )
                extraction_mapping[username][info["stableUserId"]].append(
                    activities_shm
                )

        logging.info("Extracting: {}".format(ujson.dumps(extraction_mapping, indent=2)))
        for username in extraction_mapping.keys():
            for cdp_location in extraction_mapping[username]:
                extraction_set = self.temp_manager.get_extraction_set(
                    username, cdp_location
                )
                for file_location in extraction_mapping[username][cdp_location]:
                    tsk_file = None
                    try:
                        tsk_file = self.tsk_fs.open(file_location)
                    except Exception as error:
                        logging.error(
                            "Could not extract file: {} [error: {}]".format(
                                file_location, error
                            )
                        )
                        continue

                    extraction_set.extract_file(tsk_file, file_location)

                db_location = extraction_set.get_activities_location()
                activities_db = ActivitiesDb(db_location)
                formatter = None
                if self.output_template:
                    formatter = CustomStringFormatter()

                if self.dump_db:
                    for record in activities_db.iter_records():
                        formatted_record = record.as_ordered_dict()
                        formatted_record.insert(0, ("_table", record._table))
                        if formatter:
                            output = formatter.format(
                                self.output_template, **formatted_record
                            )
                            print(output)
                        else:
                            print(ujson.dumps(formatted_record))
                else:
                    for record in activities_db.iter_activities(0):
                        formatted_record = record.as_ordered_dict()
                        formatted_record["_user"] = username
                        formatted_record["_cpd_location"] = cdp_location
                        if formatter:
                            output = formatter.format(
                                self.output_template, **formatted_record
                            )
                            print(output)
                        else:
                            print(ujson.dumps(formatted_record))

    def _get_cpd_global_settings(self, location):
        logging.debug("Attempting to get cpd settings from: {}".format(location))

        tsk_file = None
        try:
            tsk_file = self.tsk_fs.open(location)
        except Exception as error:
            logging.debug("Could not find: {}".format(location))
            return

        data = tsk_file.read_random(0, tsk_file.info.meta.size)
        settings = ujson.loads(data.decode("utf-8-sig"))
        return settings

    def _username_list(self):
        users_dir = None
        users_folders = []
        try:
            users_dir = self.tsk_fs.open_dir("Users")
        except Exception as error:
            logging.info(
                "A user folder cannot be found for: {}".format(self.description)
            )
            return None

        for tsk_file in users_dir:
            filename = tsk_file.info.name.name.decode("utf-8")

            if filename in [".", ".."]:
                continue

            if hasattr(tsk_file.info, "meta"):
                if not hasattr(tsk_file.info.meta, "type"):
                    # logging.debug(u"not sure how to handle here...")
                    continue
            else:
                # logging.debug(u"not sure how to handle here...")
                continue

            if tsk_file.info.meta.type == pytsk3.TSK_FS_META_TYPE_DIR:
                users_folders.append(filename)

        return users_folders
