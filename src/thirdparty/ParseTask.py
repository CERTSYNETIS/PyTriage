from pathlib import Path
import xmltodict, json
from logging import Logger
from pathlib import Path


class ParseTask:
    """
    Class to Parse Windows Scheduled Task file
    """

    def __init__(
        self,
        task_file: Path,
        result_jsonl_file: Path,
        logger: Logger,
    ) -> None:
        self.task_file = task_file
        self.result_jsonl_file = result_jsonl_file
        self.logger = logger

    def write_results(self, json_data: dict, output_file: Path):
        with open(output_file, "a", encoding="utf-16", errors="ignore") as jsonfile:
            json.dump(json_data, jsonfile)
            jsonfile.write("\n")

    def analyze(self):
        try:
            self.logger.info(f"[analyze] Processing Task {self.task_file}")
            _tojson = ""
            with open(
                self.task_file.as_posix(), "r", encoding="utf-16", errors="ignore"
            ) as fd:
                _tojson = xmltodict.parse(fd.read())
                if _tojson.get("Task", None):
                    _tojson["Task"]["filename"] = self.task_file.name
            self.write_results(json_data=_tojson, output_file=self.result_jsonl_file)
        except Exception as ex:
            self.logger.error(f"[analyze] --- {ex}")
