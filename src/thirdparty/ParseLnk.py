import json
from pathlib import Path
from .triageutils import file_exists, delete_file
import LnkParse3


class ParseLnk:
    """
    Class parse prefetch
    """

    def __init__(self, lnk_file: Path, output: Path, logger) -> None:
        """
        The constructor for LnkParser class.
        """
        self.lnk_file = lnk_file
        self.result = output
        self.logger = logger

    def parse_file(self, lnk_file: Path) -> dict:
        try:
            output = dict()
            with open(lnk_file, "rb") as indata:
                lnk = LnkParse3.lnk_file(indata)
                output = lnk.get_json()
        except Exception as ex:
            self.logger.error(f"[parse_file] {ex}")
        return output

    def write_results(self, json_data: dict, output_file: Path):
        with open(output_file, "w", encoding="utf-8") as jsonfile:
            json.dump(json_data, jsonfile, indent=4, default=str)

    def analyze(self):
        try:
            self.logger.info(f"[analyze] Processing Lnk {self.lnk_file}")
            _res = self.parse_file(lnk_file=self.lnk_file)
            if file_exists(file=self.result, logger=self.logger):
                delete_file(src=self.result, logger=self.logger)
            self.write_results(json_data=_res, output_file=self.result)
        except Exception as ex:
            self.logger.error(f"[analyze] --- {ex}")
