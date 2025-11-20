import json
from pathlib import Path
import pyscca


class ParsePrefetch:
    """
    Class parse prefetch
    """

    def __init__(self, prefetch: Path, output: Path, logger) -> None:
        """
        The constructor for PrefetchParser class.
        """
        self.prefetch = prefetch
        self.result = output
        self.logger = logger

    def parse_file(self, pf_file: Path):
        try:
            output = dict()
            scca = pyscca.open(str(pf_file))
            last_run_times = []
            for x in range(8):
                if scca.get_last_run_time_as_integer(x) > 0:
                    last_run_times.append(
                        scca.get_last_run_time(x).strftime("%Y-%m-%d %H:%M:%S")
                    )
                else:
                    last_run_times.append("N/A")
            output["executable"] = str(scca.executable_filename)
            output["run_count"] = str(scca.run_count)
            output["hash"] = str(scca.prefetch_hash)
            output["last_runs"] = last_run_times
            output["number_of_volumes"] = scca.number_of_volumes
            volumes = []
            for i in range(scca.number_of_volumes):
                volume = {
                    "path": str(scca.get_volume_information(i).device_path),
                    "creation_time": scca.get_volume_information(
                        i
                    ).creation_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "seriel_number": format(
                        scca.get_volume_information(i).serial_number, "x"
                    ).upper(),
                }
                volumes.append(volume)
            output["volumes"] = volumes
            output["files"] = list()
            for _i in scca.filenames:
                output["files"].append(_i)
        except Exception as ex:
            self.logger.error(f"[parse_file] {ex}")
        finally:
            return output

    def write_results(self, json_data: dict, output_file: Path):
        with open(output_file, "w", encoding="utf-8") as jsonfile:
            json.dump(json_data, jsonfile, indent=4, default=str)

    def analyze(self):
        try:
            self.logger.info(f"[analyze] Processing prefetch {self.prefetch}")
            _res = self.parse_file(pf_file=self.prefetch)
            self.write_results(json_data=_res, output_file=self.result)
        except Exception as ex:
            self.logger.error(f"[analyze] --- {ex}")
