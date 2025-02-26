import json
import os
from pathlib import Path
from regipy.registry import RegistryHive
from regipy.plugins.utils import run_relevant_plugins
from .triageutils import search_files_generator, delete_file
import datetime
import csv


class ParseRegistry:
    """
    Class to Parse Registry hives
    """

    def __init__(self, logger) -> None:
        self.logger = logger

    def parse_amcache(self, file_path, dir_out):
        """
        Main function to parse amcache with regippy
        :param file_path: str : path to the amcache file
        :param dir_out: str : path to result folder
        :return:
        """
        hv_name = file_path.name  # file_path.name
        reg = RegistryHive(file_path)
        user_name = file_path.parts[-2]
        path_out_csv = Path(os.path.join(dir_out, f"{hv_name}_{user_name}.csv"))
        delete_file(src=path_out_csv, logger=self.logger)
        path_out_json = Path(os.path.join(dir_out, f"{hv_name}_{user_name}.json"))
        delete_file(src=path_out_json, logger=self.logger)
        try:
            parsed = run_relevant_plugins(reg, as_json=True)
            with open(path_out_json, "w") as outfile:
                json.dump(parsed, outfile, indent=4)

            entry = parsed.get("amcache", [])
            l_not_sorted = []
            header_list = ["Date", "Time", "Name", "Hash"]
            for val in entry:
                timestamp = val.get("timestamp")
                name = str(val.get("original_file_name", "-")).strip()
                if name == "-" or name == "0" or name == "":
                    name = val.get("name", "-")
                if name == "-" or name == "0" or name == "":
                    name = val.get("full_path", "-")
                sha1 = val.get("sha1", "-")
                output = "{}|{}|{}".format(timestamp, name, sha1)
                l_not_sorted.append(output)
            if l_not_sorted:
                self.format_and_write_to_csv(path_out_csv, l_not_sorted, header_list)
        except Exception as ex:
            self.logger.error(f"[parse_amcache] {ex}")

    def parse_software(self, file_path, dir_out):
        """
        Main function to parse software hive with regippy
        :param file_path: str : path to the software file
        :param dir_out: str : path to result folder
        :return:
        """
        hv_name = file_path.name
        reg = RegistryHive(file_path)
        user_name = file_path.parts[-2]
        path_out_csv = Path(
            os.path.join(dir_out, f"{hv_name}_{user_name}.csv")
        )  # os.path.join(dir_out, "{}.csv".format(hv_name))
        path_out_json = Path(os.path.join(dir_out, f"{hv_name}_{user_name}.json"))  #
        # Iterate over a registry hive recursively:
        try:
            parsed = run_relevant_plugins(reg, as_json=True)
            with open(path_out_json, "w") as outfile:
                json.dump(parsed, outfile, indent=4)

            with open(path_out_csv, "w") as file_out:
                for value in parsed.values():
                    for key in value:
                        if type(key) == dict:
                            key = (
                                json.dumps(key)
                                .replace(",", "|")
                                .replace("{", "|")
                                .replace("}", "|")
                            )
                        file_out.write(key)
                        file_out.write("\n")
        except Exception as ex:
            self.logger.error(f"[parse_software] {ex}")

    def parse_system(self, file_path, dir_out):
        """
        Main function to parse system hive with regippy
        :param file_path: str : path to the software file
        :param dir_out: str : path to result folder
        :return:
        """
        hv_name = file_path.name
        reg = RegistryHive(file_path)
        user_name = file_path.parts[-2]
        path_out_csv = Path(
            os.path.join(dir_out, f"{hv_name}_{user_name}.csv")
        )  # os.path.join(dir_out, "{}.csv".format(hv_name))
        path_out_json = Path(os.path.join(dir_out, f"{hv_name}_{user_name}.json"))  #
        # Iterate over a registry hive recursively:
        try:
            parsed = run_relevant_plugins(reg, as_json=True)
            with open(path_out_json, "w") as outfile:
                json.dump(parsed, outfile, indent=4)

            with open(path_out_csv, "w") as file_out:
                for value in parsed.values():
                    for key in value:
                        if type(key) == dict:
                            key = (
                                json.dumps(key)
                                .replace(",", "|")
                                .replace("{", "|")
                                .replace("}", "|")
                            )
                        file_out.write(key)
                        file_out.write("\n")
        except Exception as ex:
            self.logger.error(f"[parse_system] {ex}")

    def parse_security(self, file_path, dir_out):
        """
        Main function to parse security hive with regippy
        :param file_path: str : path to the software file
        :param dir_out: str : path to result folder
        :return:
        """
        hv_name = file_path.name
        reg = RegistryHive(file_path)
        # Iterate over a registry hive recursively:
        user_name = file_path.parts[-2]
        path_out_csv = Path(
            os.path.join(dir_out, f"{hv_name}_{user_name}.csv")
        )  # os.path.join(dir_out, "{}.csv".format(hv_name))
        path_out_json = Path(os.path.join(dir_out, f"{hv_name}_{user_name}.json"))  #
        # Iterate over a registry hive recursively:
        try:
            parsed = run_relevant_plugins(reg, as_json=True)
            with open(path_out_json, "w") as outfile:
                json.dump(parsed, outfile, indent=4)

            with open(path_out_csv, "a") as file_out:
                for value in parsed.values():
                    for key in value:
                        if type(key) == dict:
                            key = (
                                json.dumps(key)
                                .replace(",", "|")
                                .replace("{", "|")
                                .replace("}", "|")
                            )
                        file_out.write(key)
                        file_out.write("\n")
        except Exception as ex:
            self.logger.error(f"[parse_security] {ex}")

    def parse_ntuser(self, file_path, dir_out):
        """
        Main function to parse ntuser hive with regippy
        :param file_path: str : path to the ntuser file
        :param dir_out: str : path to result folder
        :return:
        """
        # Not done yet
        hv_name = file_path.name
        reg = RegistryHive(file_path)
        user_name = file_path.parts[-2]
        path_out_csv = Path(
            os.path.join(dir_out, f"{hv_name}_{user_name}.csv")
        )  # os.path.join(dir_out, "{}_{}.csv".format(hv_name, user_name))
        path_out_json = Path(
            os.path.join(dir_out, f"{hv_name}_{user_name}.json")
        )  # os.path.join(dir_out, "{}_{}.json".format(hv_name, user_name))
        try:
            parsed = run_relevant_plugins(reg, as_json=True)
            with open(path_out_json, "w") as outfile:
                json.dump(parsed, outfile, indent=4)

        except Exception as ex:
            self.logger.error(f"[parse_ntuser] {ex}")

    def parse_shimcash(self, file_path, dir_out):
        """
        Main function to parse shimcash app compat hive with regippy
        :param file_path: str : path to the appcompat file
        :param dir_out: str : path to result folder
        :return:
        """
        # Not done yet
        pass

    def parse_all(self, dir_to_reg, out_folder):
        """
        Main function to parse all hive with regippy
        :param dir_to_reg: str : path to the folder containing all hives to parse
        :param out_folder: str : path to result folder
        :return:
        """

        for _f in search_files_generator(
            src=dir_to_reg, pattern="Amcache.hve", strict=True, logger=self.logger
        ):
            relative_file_path = _f
            absolute_file_path = (
                relative_file_path.absolute()
            )  # absolute is a Path object
            self.parse_amcache(absolute_file_path, out_folder)

        for _f in search_files_generator(
            src=dir_to_reg, pattern="SECURITY", strict=True, logger=self.logger
        ):
            relative_file_path = _f
            absolute_file_path = (
                relative_file_path.absolute()
            )  # absolute is a Path object
            self.parse_security(absolute_file_path, out_folder)

        for _f in search_files_generator(
            src=dir_to_reg, pattern="SYSTEM", strict=True, logger=self.logger
        ):
            relative_file_path = _f
            absolute_file_path = (
                relative_file_path.absolute()
            )  # absolute is a Path object
            self.parse_system(absolute_file_path, out_folder)

        for _f in search_files_generator(
            src=dir_to_reg, pattern="SOFTWARE", strict=True, logger=self.logger
        ):
            relative_file_path = _f
            absolute_file_path = (
                relative_file_path.absolute()
            )  # absolute is a Path object
            self.parse_software(absolute_file_path, out_folder)

        for _f in search_files_generator(
            src=dir_to_reg, pattern="NTUSER.DAT", strict=True, logger=self.logger
        ):
            relative_file_path = _f
            absolute_file_path = (
                relative_file_path.absolute()
            )  # absolute is a Path object
            self.parse_ntuser(absolute_file_path, out_folder)

    def format_list_user_friendly(self, list_to_format):
        """
        To format a list to a human-readable format DATE|TIME|ETC|ETC
        :param list_to_format: list : list to be formated
        :return: list : human readble sorted list
        """
        list_sorted = []
        lines = sorted(list_to_format, key=lambda line: line.split("|")[0])
        for line_sorted in lines:
            splited_line = line_sorted.split("|")
            splited_line[0] = splited_line[0].replace("T", "|").split(".")[0]
            list_sorted.append("|".join(splited_line))
        return list_sorted

    def write_report_as_csv_file(self, path_to_file, l_content):
        """
        Function to write a report  on a file.
        Parameters:
            path_to_file (str) path of the file to write to
            l_content (list(str)) a list of string
        """
        try:
            with open(path_to_file, "a") as obs_file:
                for line in l_content:
                    obs_file.write(line)
                    obs_file.write("\n")
        except Exception as ex:
            self.logger.error(f"[write_report_as_csv_file] {ex}")

    def format_and_write_to_csv(self, out_file, l_to_process, header):
        """
        To format a list to a nice human-readable csv
        :param out_file: str : path to file where the result will be written
        :param l_to_process: list : list to be formated to human-readble
        :param header: list : header that will be writted at the top of the csv file
        :return:
        """
        l_formated = self.format_list_user_friendly(l_to_process)
        l_formated.insert(0, "|".join(header))
        self.write_report_as_csv_file(out_file, l_formated)

    def convert_epoch_and_sort(self, in_file):
        """sort a CSV by date and convert epoch ts to current.

        Args:
            in_file (str): path to csv file.
        """

        with open(in_file, "r") as file:
            next(file)
            reader = csv.reader(file, delimiter="|")
            lines = list(reader)

            def sort_key(ligne):
                try:
                    timestamp = int(ligne[0])
                    return datetime.datetime.fromtimestamp(timestamp)
                except:
                    return datetime.datetime.now()

            lines.sort(key=sort_key, reverse=False)
            for line in lines:
                try:
                    timestamp = int(line[0])
                    formatted_timestamp = datetime.datetime.fromtimestamp(
                        timestamp
                    ).strftime("%Y-%m-%d|%H:%M:%S")
                    line[0] = formatted_timestamp
                except:
                    continue
        return lines

    def parse_hive_from_rr(self, hv_name, path_to_hive, path_to_result_dir):
        try:
            processed = self.convert_epoch_and_sort(path_to_hive)

            with open(
                os.path.join(path_to_result_dir, "{}.csv".format(hv_name)), "a"
            ) as res_file:
                writer = csv.writer(res_file, delimiter="|")
                writer.writerows(processed)

            if "system" in hv_name.lower():
                l_shimcache = self.get_shimcache_from_system_rr(processed)

                with open(
                    os.path.join(path_to_result_dir, "appcompat.csv"), "a"
                ) as res_file:
                    for line in l_shimcache:
                        res_file.write(line)
                        res_file.write("\n")
        except Exception as ex:
            self.logger.error(f"[parse_hive_from_rr] {ex}")

    def get_shimcache_from_system_rr(self, l_system):
        l_shimcache = ["DATE|TIME|ENTRY"]
        for line in l_system:
            if len(line) >= 4:
                if "AppCompatCache" in line[4]:
                    date_time = line[0]
                    entry = (
                        line[4]
                        .replace("M...", "")
                        .replace("AppCompatCache", "")
                        .lstrip()
                    )
                    l_shimcache.append("{}|{}".format(date_time, entry))
        return l_shimcache
