import csv
from .constants import *
from .mft_record import MftRecord


class MftAnalyzer:
    def __init__(
        self,
        mft_file: str,
        output_file: str,
        debug: int = 0,
        verbosity: int = 0,
        compute_hashes: bool = False,
        export_format: str = "csv",
        logger=None,
    ) -> None:
        self.mft_file = mft_file
        self.output_file = output_file
        self.debug = debug
        self.verbosity = int(verbosity)
        self.compute_hashes = compute_hashes
        self.export_format = export_format
        self.csvfile = None
        self.csv_writer = None
        self.logger = logger
        self.mft_records = {}
        self.stats = {
            "total_records": 0,
            "active_records": 0,
            "directories": 0,
            "files": 0,
        }
        if self.compute_hashes:
            self.stats.update(
                {
                    "unique_md5": set(),
                    "unique_sha256": set(),
                    "unique_sha512": set(),
                    "unique_crc32": set(),
                }
            )

    def analyze(self) -> None:
        try:
            self.logger.info("Starting MFT analysis...")
            self.initialize_csv_writer()
            self.process_mft()
            self.write_remaining_records()
        except Exception as e:
            self.logger.error(f"An unexpected error occurred: {e}")
        finally:
            if self.csvfile:
                self.csvfile.close()
            else:
                self.logger.info("Analysis complete.")
            self.print_statistics()

    def process_mft(self) -> None:
        self.logger.info(f"Processing MFT file: {self.mft_file}")
        try:
            with open(self.mft_file, "rb") as f:
                while True:
                    raw_record = self.read_record(f)
                    if not raw_record:
                        break

                    try:
                        # self.logger.debug(f"Processing record {self.stats['total_records']}")
                        record = MftRecord(raw_record, self.compute_hashes)
                        # self.logger.debug(f"Record parsed, recordnum: {record.recordnum}")
                        self.stats["total_records"] += 1

                        if record.flags & FILE_RECORD_IN_USE:
                            self.stats["active_records"] += 1
                        if record.flags & FILE_RECORD_IS_DIRECTORY:
                            self.stats["directories"] += 1
                        else:
                            self.stats["files"] += 1

                        self.mft_records[record.recordnum] = record

                        if self.debug >= 2:
                            self.logger.debug(
                                f"Processed record {self.stats['total_records']}: {record.filename}"
                            )

                        if self.stats["total_records"] % 1000 == 0:
                            self.write_csv_block()
                            self.mft_records.clear()

                    except Exception as e:
                        self.logger.error(
                            f"Error processing record {self.stats['total_records']}: {str(e)}"
                        )
                        self.logger.error(
                            f"Raw record (first 100 bytes): {raw_record[:100].hex()}"
                        )
                        continue

        except Exception as e:
            self.logger.error(f"Error reading MFT file: {str(e)}")

        self.logger.info(
            f"MFT processing complete. Total records processed: {self.stats['total_records']}"
        )

    def read_record(self, file):
        return file.read(MFT_RECORD_SIZE)

    def initialize_csv_writer(self):
        if self.csvfile is None:
            self.csvfile = open(self.output_file, "w", newline="", encoding="utf-8")
            self.csv_writer = csv.writer(self.csvfile)
            self.csv_writer.writerow(CSV_HEADER)

    def write_csv_block(self) -> None:
        # self.logger.info(f"Writing CSV block. Records in block: {len(self.mft_records)}")
        try:
            if self.csv_writer is None:
                self.initialize_csv_writer()

            for record in self.mft_records.values():
                try:
                    filepath = self.build_filepath(record)
                    csv_row = record.to_csv()
                    csv_row[-1] = filepath

                    csv_row = [str(item) for item in csv_row]

                    self.csv_writer.writerow(csv_row)
                    if self.debug:
                        self.logger.debug(f"Wrote record {record.recordnum} to CSV")
                except Exception as e:
                    self.logger.error(
                        f"Error writing record {record.recordnum}: {str(e)}"
                    )

            if self.csvfile:
                self.csvfile.flush()
            # self.logger.info(f"CSV block written. Current file size: {self.csvfile.tell() if self.csvfile else 0} bytes")
        except Exception as e:
            self.logger.error(f"Error in write_csv_block: {str(e)}")

    def write_remaining_records(self) -> None:
        self.write_csv_block()
        self.mft_records.clear()

    def build_filepath(self, record: MftRecord) -> str:
        path_parts = []
        current_record = record
        max_depth = 255

        while current_record and max_depth > 0:
            if current_record.recordnum == 5:
                path_parts.insert(0, "")
                break
            elif current_record.filename:
                path_parts.insert(0, current_record.filename)
            else:
                path_parts.insert(0, f"Unknown_{current_record.recordnum}")

            parent_record_num = current_record.get_parent_record_num()

            if parent_record_num == current_record.recordnum:
                path_parts.insert(0, "OrphanedFiles")
                break

            current_record = self.mft_records.get(parent_record_num)
            if not current_record:
                path_parts.insert(0, f"UnknownParent_{parent_record_num}")
                break

            max_depth -= 1

        if max_depth == 0:
            path_parts.insert(0, "DeepPath")

        return "\\".join(path_parts)

    def print_statistics(self) -> None:
        self.logger.info("MFT Analysis Statistics:")
        self.logger.info(f"Total records processed: {self.stats['total_records']}")
        self.logger.info(f"Active records: {self.stats['active_records']}")
        self.logger.info(f"Directories: {self.stats['directories']}")
        self.logger.info(f"Files: {self.stats['files']}")
        if self.compute_hashes:
            self.logger.info(f"Unique MD5 hashes: {len(self.stats['unique_md5'])}")
            self.logger.info(
                f"Unique SHA256 hashes: {len(self.stats['unique_sha256'])}"
            )
            self.logger.info(
                f"Unique SHA512 hashes: {len(self.stats['unique_sha512'])}"
            )
            self.logger.info(f"Unique CRC32 hashes: {len(self.stats['unique_crc32'])}")
