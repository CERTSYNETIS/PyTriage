import os
import logging
import yaml
import pkg_resources
from datetime import datetime
from src.thirdparty import triageutils
from src.thirdparty import admin_utils
from src.thirdparty.AESCipher import AESCipher
from src.thirdparty.logging import get_logger
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
import hashlib
import uuid
import ssl
import psutil
from slugify import slugify
from importlib import import_module
from celery import Celery
from celery.result import AsyncResult


INTERNAL_CONFIG = triageutils.INTERNAL_CONFIG
UPLOAD_FOLDER = INTERNAL_CONFIG["general"]["upload"]  # /data"
LOG_FOLDER = INTERNAL_CONFIG["general"]["logfolder"]  # /log"

celery = Celery(__name__)
celery.conf.broker_url = os.environ.get("CELERY_BROKER_URL", "redis://redis:6379/0")
celery.conf.result_backend = os.environ.get(
    "CELERY_RESULT_BACKEND", "redis://redis:6379/0"
)
celery.conf.task_track_started = True
celery.conf.result_persistent = True

app = Flask(__name__)


def recursive_items(dictionary=None):
    for key, value in dictionary.items():
        if type(value) is dict:
            yield (key, value)
            yield from recursive_items(value)
        else:
            yield (key, value)


def check_config(conf=""):
    try:
        keys = []
        for k, _ in recursive_items(conf):
            keys.append(k)
        if "uuid" not in keys:
            raise Exception("[check_config] uuid key not in config")
        if "client" not in keys:
            raise Exception("[check_config] client key not in config")
        if "hostname" not in keys:
            raise Exception("[check_config] hostname key not in config")
        if "timesketch_id" not in keys:
            raise Exception("[check_config] timesketch_id key not in config")
        if "run" not in keys:
            raise Exception("[check_config] run key not in config")
        if "archive" not in keys:
            raise Exception("[check_config] archive key not in config")
        if "auto_close_collecte" not in keys:
            raise Exception("[check_config] auto_close_collecte key not in config")
    except Exception as err:
        raise err


def generate_entry_points():
    """Walk through plugins folder to generate entry points
    Returns:
        entry points dictionary
    """
    script_folder = os.path.dirname(os.path.realpath(__file__))
    entry_points = {"triage_plugins": [], "console_scripts": []}
    entry_points["console_scripts"].append("pytriage = triage:main")

    plugins_folder = os.path.join(script_folder, "src", "plugins")
    for plugin_file in os.listdir(plugins_folder):
        if not plugin_file.endswith(".py") or plugin_file == "__init__.py":
            continue
        plugin_name = plugin_file[:-3]
        entry_points["triage_plugins"].append(
            {
                "name": plugin_name,
                "file": f"src.plugins.{plugin_name}",
                "class": "Plugin",
            }
        )
    return entry_points


def load_plugin_old(plugin_name):
    """Récupération du plugin
    Args:
        plugin_name (str): nom du plugin souhaité
    Returns:
        La classe souhiatée (advertised Python object)
    """
    eps = generate_entry_points()
    for ep in pkg_resources.iter_entry_points(group="triage_plugins"):
        print(ep)
        if ep.name == plugin_name:
            return ep.load()
    raise ValueError(f"No such plugin: {plugin_name}")


def load_plugin(plugin_name, entry_points):
    """Récupération du plugin
    Args:
        plugin_name (str): nom du plugin souhaité
    Returns:
        La classe souhiatée (advertised Python object)
    """
    for ep in entry_points["triage_plugins"]:
        if ep["name"] == plugin_name:
            module = import_module(ep["file"])
            my_class = getattr(module, ep["class"])
            return my_class
    raise ValueError(f"No such plugin: {plugin_name}")


@app.route("/", methods=["GET"])
def home():
    admin_get_ts_status()
    return render_template(
        "index.html",
        timesketchurl=INTERNAL_CONFIG["general"]["timesketch_url"],
        elkurl=INTERNAL_CONFIG["general"]["kibana_url"],
    )


@app.route("/admin", methods=["GET"])
def admin_page():
    return render_template(
        "admin.html",
        timesketchurl=INTERNAL_CONFIG["general"]["timesketch_url"],
        elkurl=INTERNAL_CONFIG["general"]["kibana_url"],
    )


@app.route("/collecte/<string:uuid>", methods=["GET"])
def collecte_page(uuid: str = None):
    _opened = True
    if not uuid:
        _config = generate_config()
    else:
        _config = _get_collecte_by_id(uuid=uuid)
    if not _config.get("uuid", ""):
        return home()
    return render_template(
        "collecte_details.html",
        timesketchurl=INTERNAL_CONFIG["general"]["timesketch_url"],
        elkurl=INTERNAL_CONFIG["general"]["kibana_url"],
        config=_config,
    )


def generate_config() -> dict:
    res = dict()
    res["uuid"] = ""
    res["task_id"] = ""
    res["general"] = dict()
    res["general"]["extract"] = ""
    res["general"]["extracted_zip"] = ""
    res["general"]["client"] = ""
    res["general"]["hostname"] = ""
    res["general"]["timesketch_id"] = 0
    res["general"]["replay"] = 0
    res["general"]["auto_close_collecte"] = True
    res["path"] = ""
    res["log_file"] = ""
    res["run"] = dict()
    res["run"]["kape"] = dict()
    res["run"]["kape"]["plugin"] = False
    res["run"]["kape"]["evtx"] = False
    res["run"]["kape"]["iis"] = False
    res["run"]["kape"]["timeline"] = False
    res["run"]["kape"]["winlogbeat"] = False
    res["run"]["kape"]["registry"] = False
    res["run"]["kape"]["usnjrnl"] = False
    res["run"]["kape"]["mft"] = False
    res["run"]["kape"]["prefetch"] = False
    res["run"]["kape"]["mplog"] = False
    res["run"]["kape"]["activitiescache"] = False

    res["run"]["uac"] = dict()
    res["run"]["uac"]["plugin"] = False
    res["run"]["uac"]["filebeat"] = False
    res["run"]["uac"]["timeline"] = False

    res["run"]["volatility"] = dict()
    res["run"]["volatility"]["plugin"] = False
    res["run"]["volatility"]["pslist"] = False
    res["run"]["volatility"]["pstree"] = False
    res["run"]["volatility"]["netscan"] = False
    res["run"]["volatility"]["netstat"] = False

    res["run"]["adtimeline"] = False
    res["run"]["o365"] = False

    res["run"]["generaptor"] = dict()
    res["run"]["generaptor"]["plugin"] = False
    res["run"]["generaptor"]["private_key_file"] = ""
    res["run"]["generaptor"]["private_key_secret"] = ""
    res["run"]["generaptor"]["evtx"] = False
    res["run"]["generaptor"]["winlogbeat"] = False
    res["run"]["generaptor"]["iis"] = False
    res["run"]["generaptor"]["timeline"] = False
    res["run"]["generaptor"]["registry"] = False
    res["run"]["generaptor"]["mft"] = False
    res["run"]["generaptor"]["usnjrnl"] = False
    res["run"]["generaptor"]["prefetch"] = False
    res["run"]["generaptor"]["mplog"] = False
    res["run"]["generaptor"]["linux"] = False
    res["run"]["generaptor"]["activitiescache"] = False

    res["run"]["orc"] = dict()
    res["run"]["orc"]["plugin"] = False
    res["run"]["orc"]["private_key_file"] = ""
    res["run"]["orc"]["evtx"] = False
    res["run"]["orc"]["winlogbeat"] = False
    res["run"]["orc"]["iis"] = False
    res["run"]["orc"]["timeline"] = False
    res["run"]["orc"]["registry"] = False
    res["run"]["orc"]["mft"] = False
    res["run"]["orc"]["usnjrnl"] = False
    res["run"]["orc"]["prefetch"] = False
    res["run"]["orc"]["mplog"] = False
    res["run"]["orc"]["activitiescache"] = False

    res["run"]["adaudit"] = dict()
    res["run"]["adaudit"]["plugin"] = False

    res["run"]["standalone"] = dict()
    res["run"]["standalone"]["plugin"] = False
    res["run"]["standalone"]["hayabusa"] = False
    res["run"]["standalone"]["evtx"] = False
    res["run"]["standalone"]["winlogbeat"] = False
    res["run"]["standalone"]["fortinet"] = False
    res["run"]["standalone"]["forcepoint"] = False

    res["run"]["hayabusa"] = False

    res["archive"] = dict()
    res["archive"]["name"] = ""
    res["archive"]["sha256"] = ""
    res["error"] = ""
    return res


@app.route("/usage", methods=["GET"])
def get_cpu_memory_usage():
    cpu_usage = psutil.cpu_percent()
    memory_usage = psutil.virtual_memory().percent
    disk_partitions = psutil.disk_partitions()
    disk_usage = 0
    for partition in disk_partitions:
        if partition.mountpoint == "/data":
            disk_usage = psutil.disk_usage(partition.mountpoint).percent
    return jsonify(cpu=cpu_usage, memory=memory_usage, disk=disk_usage)


@app.route("/", methods=["POST"])
def set_input_files():
    try:
        res = generate_config()
        collecte_id = str(uuid.uuid4())
        l = get_logger(name=collecte_id)
        if not request.form.get("client", None):
            raise Exception("No valid input")
        ex_dir = os.path.join(UPLOAD_FOLDER, collecte_id)
        triageutils.set_logger(l)
        triageutils.create_directory_path(path=ex_dir, logger=l)

        res["uuid"] = collecte_id
        res["general"]["extract"] = ex_dir
        res["general"]["client"] = (
            slugify(request.form["client"]) if request.form.get("client") else ""
        )
        res["general"]["hostname"] = (
            slugify(request.form["hostname"]) if request.form.get("hostname") else ""
        )
        res["general"]["timesketch_id"] = 0
        res["general"]["replay"] = 0
        res["general"]["auto_close_collecte"] = True

        if not res["general"]["client"] or not res["general"]["hostname"]:
            l.error("[set_input_files] Client or Hostname NOT SET")
            res["error"] = "[set_input_files] Client or Hostname NOT SET"

        res["path"] = ex_dir
        res["log_file"] = f"{collecte_id}.log"

        ##RUN KAPE
        res["run"]["kape"]["plugin"] = True if "kape" in request.form else False
        if res["run"]["kape"]["plugin"]:
            res["run"]["kape"]["evtx"] = True if "kape_evtx" in request.form else False
            res["run"]["kape"]["iis"] = True if "kape_iis" in request.form else False
            res["run"]["kape"]["registry"] = (
                True if "kape_registry" in request.form else False
            )
            res["run"]["kape"]["mft"] = True if "kape_mft" in request.form else False
            res["run"]["kape"]["usnjrnl"] = (
                True if "kape_usnjrnl" in request.form else False
            )
            res["run"]["kape"]["prefetch"] = (
                True if "kape_prefetch" in request.form else False
            )
            res["run"]["kape"]["mplog"] = (
                True if "kape_mplog" in request.form else False
            )
            res["run"]["kape"]["activitiescache"] = (
                True if "kape_activitiescache" in request.form else False
            )
            res["run"]["kape"]["timeline"] = (
                True if "kape_timeline" in request.form else False
            )
            res["run"]["kape"]["winlogbeat"] = (
                True if "kape_evtx_winlogbeat" in request.form else False
            )
            if not res["run"]["kape"]["evtx"]:
                res["run"]["kape"]["winlogbeat"] = False

        ##RUN UAC
        res["run"]["uac"]["plugin"] = True if "uac" in request.form else False
        if res["run"]["uac"]["plugin"]:
            res["run"]["uac"]["filebeat"] = (
                True if "uac_filebeat" in request.form else False
            )
            res["run"]["uac"]["timeline"] = (
                True if "uac_timeline" in request.form else False
            )

        ##RUN VOLATILITY
        res["run"]["volatility"]["plugin"] = (
            True if "volatility" in request.form else False
        )
        if res["run"]["volatility"]["plugin"]:
            res["run"]["volatility"]["pslist"] = (
                True if "volatility_pslist" in request.form else False
            )
            res["run"]["volatility"]["pstree"] = (
                True if "volatility_pstree" in request.form else False
            )
            res["run"]["volatility"]["netscan"] = (
                True if "volatility_netscan" in request.form else False
            )
            res["run"]["volatility"]["netstat"] = (
                True if "volatility_netstat" in request.form else False
            )

        ##RUN ADTIMELINE
        res["run"]["adtimeline"] = True if "adtimeline" in request.form else False

        ##RUN O365
        res["run"]["o365"] = True if "o365" in request.form else False

        ##RUN ORC
        res["run"]["orc"]["plugin"] = True if "orc" in request.form else False
        if res["run"]["orc"]["plugin"]:
            res["run"]["orc"]["private_key_file"] = ""
            res["run"]["orc"]["evtx"] = True if "orc_evtx" in request.form else False
            res["run"]["orc"]["winlogbeat"] = (
                True if "orc_evtx_winlogbeat" in request.form else False
            )
            if not res["run"]["orc"]["evtx"]:
                res["run"]["orc"]["winlogbeat"] = False
            res["run"]["orc"]["iis"] = True if "orc_iis" in request.form else False
            res["run"]["orc"]["registry"] = (
                True if "orc_registry" in request.form else False
            )
            res["run"]["orc"]["mft"] = True if "orc_mft" in request.form else False
            res["run"]["orc"]["usnjrnl"] = (
                True if "orc_usnjrnl" in request.form else False
            )
            res["run"]["orc"]["timeline"] = (
                True if "orc_timeline" in request.form else False
            )
            res["run"]["orc"]["prefetch"] = (
                True if "orc_prefetch" in request.form else False
            )
            res["run"]["orc"]["activitiescache"] = (
                True if "orc_activitiescache" in request.form else False
            )
            res["run"]["orc"]["mplog"] = True if "orc_mplog" in request.form else False
            try:
                if "orc_keyfile" in request.files:
                    if request.files["orc_keyfile"]:
                        uploaded_file = request.files["orc_keyfile"]
                        filename = secure_filename(uploaded_file.filename)
                        uploaded_file.save(os.path.join(ex_dir, filename))
                        res["run"]["orc"]["private_key_file"] = filename
            except Exception as file_error:
                filename = "ERROR_filename"
                res["run"]["orc"]["private_key_file"] = filename
                l.error(
                    f"[set_input_files] ORC private key file upload error: {file_error}"
                )
                res[
                    "error"
                ] = f"[set_input_files] ORC private key file upload error: {file_error}"

        ##RUN ADAUDIT
        res["run"]["adaudit"]["plugin"] = True if "adaudit" in request.form else False

        ##RUN GENERAPTOR
        res["run"]["generaptor"]["plugin"] = (
            True if "generaptor" in request.form else False
        )
        if res["run"]["generaptor"]["plugin"]:
            if not request.form.get("generaptor_private_key_secret", ""):
                raise Exception("No generaptor private key secret")

            res["run"]["generaptor"]["private_key_file"] = ""
            _AESprivkey = AESCipher(key=collecte_id)
            _ciphered_key = _AESprivkey.encrypt(
                raw=request.form.get("generaptor_private_key_secret")
            )
            res["run"]["generaptor"]["private_key_secret"] = _ciphered_key.decode(
                "utf-8"
            )
            res["run"]["generaptor"]["evtx"] = (
                True if "generaptor_evtx" in request.form else False
            )
            res["run"]["generaptor"]["winlogbeat"] = (
                True if "generaptor_evtx_winlogbeat" in request.form else False
            )
            if not res["run"]["generaptor"]["evtx"]:
                res["run"]["generaptor"]["winlogbeat"] = False
            res["run"]["generaptor"]["iis"] = (
                True if "generaptor_iis" in request.form else False
            )
            res["run"]["generaptor"]["registry"] = (
                True if "generaptor_registry" in request.form else False
            )
            res["run"]["generaptor"]["mft"] = (
                True if "generaptor_mft" in request.form else False
            )
            res["run"]["generaptor"]["usnjrnl"] = (
                True if "generaptor_usnjrnl" in request.form else False
            )
            res["run"]["generaptor"]["timeline"] = (
                True if "generaptor_timeline" in request.form else False
            )
            res["run"]["generaptor"]["prefetch"] = (
                True if "generaptor_prefetch" in request.form else False
            )
            res["run"]["generaptor"]["mplog"] = (
                True if "generaptor_mplog" in request.form else False
            )
            res["run"]["generaptor"]["activitiescache"] = (
                True if "generaptor_activitiescache" in request.form else False
            )
            res["run"]["generaptor"]["linux"] = (
                True if "generaptor_linux" in request.form else False
            )
            try:
                if "generaptor_private_key_file" in request.files:
                    if request.files["generaptor_private_key_file"]:
                        uploaded_file = request.files["generaptor_private_key_file"]
                        filename = secure_filename(uploaded_file.filename)
                        uploaded_file.save(os.path.join(ex_dir, filename))
                        res["run"]["generaptor"]["private_key_file"] = filename
                    else:
                        raise Exception("No private key send")
            except Exception as file_error:
                filename = "ERROR_filename"
                res["run"]["generaptor"]["private_key_file"] = filename
                l.error(
                    f"[set_input_files] GENERAPTOR private key file upload error: {file_error}"
                )
                res[
                    "error"
                ] = f"[set_input_files] GENERAPTOR private key file upload error: {file_error}"

        ##RUN HAYABUSA
        res["run"]["hayabusa"] = True if "hayabusa" in request.form else False

        try:
            uploaded_file = request.files["archive"]
            filename = secure_filename(uploaded_file.filename)
            uploaded_file.save(os.path.join(ex_dir, filename))
            sha256 = hashlib.sha256()
            with open(os.path.join(ex_dir, filename), "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256.update(byte_block)
            file_sha256 = sha256.hexdigest()
        except Exception as file_error:
            filename = "ERROR_filename"
            file_sha256 = "ERROR_SHA"
            l.error(f"[set_input_files] Archive upload error: {file_error}")
            res["error"] = f"[set_input_files] Archive upload error: {file_error}"
        res["archive"]["name"] = filename
        res["archive"]["sha256"] = file_sha256

        try:
            if (
                res["run"]["kape"]["timeline"]
                or res["run"]["uac"]["timeline"]
                or res["run"]["generaptor"]["timeline"]
            ):
                _sketch = triageutils.get_sketch_by_name(
                    name=res["general"]["client"].lower(), logger=l
                )
                if not _sketch:
                    res["general"]["timesketch_id"] = triageutils.create_sketch(
                        name=res["general"]["client"].lower(), logger=l
                    )
                    l.info(
                        f'[set_input_files] New sketch ID: {res["general"]["timesketch_id"]}'
                    )
                    if res["general"]["timesketch_id"] == 0:
                        raise Exception("Error in sketch creation")
                else:
                    res["general"]["timesketch_id"] = _sketch.id
                    l.info(
                        f'[set_input_files] Sketch ID: {res["general"]["timesketch_id"]}'
                    )
            else:
                res["general"]["timesketch_id"] = 0
                l.info("[set_input_files] Plugin timeline not selected -> no sketch")
        except Exception as ex:
            res["general"]["timesketch_id"] = 0
            res["run"]["kape"]["timeline"] = False
            res["run"]["uac"]["timeline"] = False
            res["run"]["generaptor"]["timeline"] = False
            l.error(f"[set_input_files] create sketch error: {ex}")

        # if (
        #     res["run"]["hayabusa"]
        #     and not res["run"]["kape"]["evtx"]
        #     and not res["run"]["generaptor"]["evtx"]
        #     and not res["run"]["orc"]["evtx"]
        # ):
        #     res["run"]["hayabusa"] = False
        #     l.error(
        #         "[set_input_files] Cannot excute Hayabusa without kape/generaptor evtx"
        #     )
        with open(os.path.join(ex_dir, "config.yaml"), "w") as config_file:
            yaml.dump(res, config_file, sort_keys=False)
            l.info(
                f'[set_input_files] Config file created: {os.path.join(ex_dir, "config.yaml")}'
            )
    except Exception as err:
        l.error(f"[set_input_files] {str(err)}")
        res["error"] = f"[set_input_files] {str(err)}"

    return jsonify(res)


@app.route("/replay", methods=["POST"])
def replay_collecte():
    try:
        res = generate_config()
        res.update(request.json, sort_keys=False)
        _exec_hayabusa = res["run"]["hayabusa"]
        del res["run"]["hayabusa"]
        res["run"]["hayabusa"] = _exec_hayabusa
        if (
            not res.get("uuid", None)
            or not res.get("path", None)
            or not res.get("log_file", None)
        ):
            return jsonify(error=f"[replay_collecte] Bad data posted -- No UUID")
        l = get_logger(name=res["uuid"])
        res["error"] = ""
        try:
            if (
                res["run"]["kape"]["timeline"]
                or res["run"]["uac"]["timeline"]
                or res["run"]["generaptor"]["timeline"]
                or res["run"]["orc"]["timeline"]
            ) and res["general"]["timesketch_id"] == 0:
                _sketch = triageutils.get_sketch_by_name(
                    name=res["general"]["client"].lower(), logger=l
                )
                if not _sketch:
                    res["general"]["timesketch_id"] = triageutils.create_sketch(
                        name=res["general"]["client"].lower(), logger=l
                    )
                    l.info(
                        f'[replay_collecte] New sketch ID: {res["general"]["timesketch_id"]}'
                    )
                    if res["general"]["timesketch_id"] == 0:
                        raise Exception("Error in sketch creation")
                else:
                    res["general"]["timesketch_id"] = _sketch.id
                    l.info(
                        f'[replay_collecte] Sketch ID: {res["general"]["timesketch_id"]}'
                    )
        except Exception as ex:
            res["general"]["timesketch_id"] = 0
            res["run"]["kape"]["timeline"] = False
            res["run"]["uac"]["timeline"] = False
            res["run"]["generaptor"]["timeline"] = False
            l.error(f"[replay_collecte] create sketch error: {ex}")
            res["error"] = f"[replay_collecte] {ex}"

        l.info("========================= START REPLAY =========================")
        res["general"]["replay"] += 1
        l.info(f"Number Replay: {res['general']['replay']}")

        with open(os.path.join(res["path"], "config.yaml"), "w") as config_file:
            yaml.dump(res, config_file, sort_keys=False)
            l.info(
                f"[replay_collecte] config file updated: {os.path.join(res['path'], 'config.yaml')}"
            )

        return jsonify(res)
    except Exception as err:
        l.error(f"[replay_collecte] {str(err)}")
        return jsonify(error=str(err))


@app.route("/standalone_input_file", methods=["POST"])
def standalone_input_file():
    try:
        collecte_id = str(uuid.uuid4())
        ex_dir = os.path.join(UPLOAD_FOLDER, collecte_id)
        l = get_logger(name=collecte_id)
        triageutils.set_logger(l)
        triageutils.create_directory_path(path=ex_dir, logger=l)
        res = generate_config()
        res["uuid"] = collecte_id
        res["general"]["extract"] = ex_dir
        res["general"]["client"] = (
            slugify(request.form["client"]) if request.form.get("client") else ""
        )
        res["general"]["hostname"] = (
            slugify(request.form["hostname"]) if request.form.get("hostname") else ""
        )
        res["general"]["timesketch_id"] = 0
        res["general"]["replay"] = 0
        res["general"][
            "auto_close_collecte"
        ] = True  # True if request.form.get("auto_close_collecte") else False

        res["path"] = ex_dir

        res["log_file"] = f"{collecte_id}.log"

        if request.form.get("run_plugin"):
            res["run"]["standalone"]["plugin"] = True
            if request.form["run_plugin"] == "hayabusa":
                res["run"]["standalone"]["hayabusa"] = True
            elif request.form["run_plugin"] == "evtxparser":
                res["run"]["standalone"]["evtx"] = True
            elif request.form["run_plugin"] == "fortinet":
                res["run"]["standalone"]["fortinet"] = True
            elif request.form["run_plugin"] == "forcepoint":
                res["run"]["standalone"]["forcepoint"] = True
            elif request.form["run_plugin"] == "winlogbeat":
                res["run"]["standalone"]["winlogbeat"] = True

        try:
            uploaded_file = request.files["archive"]
            filename = secure_filename(uploaded_file.filename)
            uploaded_file.save(os.path.join(ex_dir, filename))
            sha256 = hashlib.sha256()
            with open(os.path.join(ex_dir, filename), "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256.update(byte_block)
            file_sha256 = sha256.hexdigest()
        except Exception as file_error:
            filename = "ERROR_filename"
            file_sha256 = "ERROR_SHA"
            l.error(f"[set_input_files] Archive upload error: {file_error}")
            return jsonify(error="Upload file error")

        res["archive"]["name"] = filename
        res["archive"]["sha256"] = file_sha256

        if not res["general"]["client"] or not res["general"]["hostname"]:
            l.error("[standalone_input_file] Client or Hostname NOT SET")
            return jsonify(error="[standalone_input_file] Client or Hostname NOT SET")
        with open(os.path.join(ex_dir, "config.yaml"), "w") as config_file:
            yaml.dump(res, config_file, sort_keys=False)
            l.info(
                f"[standalone_input_file] config file created: {os.path.join(ex_dir, 'config.yaml')}"
            )
        return jsonify(res)
    except Exception as err:
        l.error(f"[standalone_input_file] {str(err)}")
        return jsonify(error=str(err))


@app.route("/get_log", methods=["GET"])
def get_log():
    tail = []
    log_file = request.args.get("id")  # id de collecte
    if len(log_file.split("-")) != 5:
        return jsonify(error="Bad id given")
    try:
        l = logging.getLogger(f"pytriage_{log_file}")
        if not triageutils.file_exists(
            file=f"{LOG_FOLDER}/{log_file}.log", LOGLEVEL="NOLOG", logger=l
        ):
            raise Exception(f"Aucune collecte pour cet id: {log_file}")
        t_tail = []
        with open(f"{LOG_FOLDER}/{log_file}.log") as file:
            # loop to read iterate
            # last n lines and print it
            for line in file.readlines():  # [-100:]:
                t_tail.append(line)
            tail = "".join(t_tail)
        return jsonify(log=tail)
    except Exception as err:
        return jsonify(error=str(err))


@app.route("/get_all_log_files", methods=["GET"])
def get_all_log_files():
    try:
        log_files = triageutils.list_directory(
            src=LOG_FOLDER, onlyfiles=True, LOGLEVEL="NOLOG"
        )
        return jsonify(log_files=log_files)

    except Exception as err:
        return jsonify(error=str(err))


@app.route("/download_log_file", methods=["GET"])
def download_log_file():
    try:
        log_file_name = request.args.get("id")
        log_file = os.path.join(LOG_FOLDER, log_file_name)
        if triageutils.file_exists(file=log_file, LOGLEVEL="NOLOG"):
            return send_file(path_or_file=log_file, as_attachment=True)
        return jsonify(error="No log file found")
    except Exception as err:
        print(err)
        return jsonify(error=str(err))


def _get_all_opened_collectes():
    try:
        res = dict()
        sub_folders = triageutils.list_directory(
            src=UPLOAD_FOLDER, onlydirs=True, LOGLEVEL="NOLOG"
        )
        for folder in sub_folders:
            if len(folder.split("-")) == 5:
                _files = triageutils.list_directory(
                    src=os.path.join(UPLOAD_FOLDER, folder),
                    onlyfiles=True,
                    LOGLEVEL="NOLOG",
                )
                conf_file = None
                for _f in _files:
                    if _f == "config.yaml":
                        conf_file = os.path.join(UPLOAD_FOLDER, folder, _f)
                        break
                if conf_file:
                    temp_conf = triageutils.read_config(conf_file)
                    res[folder] = temp_conf["general"]["hostname"]
        return res
    except Exception as err:
        res = dict()
        res["error"] = str(err)
        return res


@app.route("/get_all_collectes", methods=["GET"])
def get_all_collectes():
    try:
        return jsonify(_get_all_opened_collectes())
    except Exception as err:
        res = dict()
        res["error"] = str(err)
        return jsonify(res)


# @app.route('/get_all_clients', methods=['GET'])
def get_all_clients():
    try:
        res = dict()
        sub_folders = triageutils.list_directory(
            src=UPLOAD_FOLDER, onlydirs=True, LOGLEVEL="NOLOG"
        )
        res["clients"] = []
        for folder in sub_folders:
            if len(folder.split("-")) == 5:
                _files = triageutils.list_directory(
                    src=os.path.join(UPLOAD_FOLDER, folder),
                    onlyfiles=True,
                    LOGLEVEL="NOLOG",
                )
                conf_file = None
                for _f in _files:
                    if _f == "config.yaml":
                        conf_file = os.path.join(UPLOAD_FOLDER, folder, _f)
                        break
                if conf_file:
                    temp_conf = triageutils.read_config(conf_file)
                    if temp_conf["general"]["client"] not in res["clients"]:
                        res["clients"].append(temp_conf["general"]["client"])
        return res
    except Exception as err:
        res = dict()
        res["error"] = str(err)
        return res  # jsonify(res)


@app.route("/get_all_clients_collectes", methods=["GET"])
def get_all_clients_collectes():
    try:
        res = dict()
        sub_folders = triageutils.list_directory(
            src=UPLOAD_FOLDER, onlydirs=True, LOGLEVEL="NOLOG"
        )
        for folder in sub_folders:
            if len(folder.split("-")) == 5:
                _files = triageutils.list_directory(
                    src=os.path.join(UPLOAD_FOLDER, folder),
                    onlyfiles=True,
                    LOGLEVEL="NOLOG",
                )
                conf_file = None
                for _f in _files:
                    if _f == "config.yaml":
                        conf_file = os.path.join(UPLOAD_FOLDER, folder, _f)
                        break
                if conf_file:
                    temp_conf = triageutils.read_config(conf_file)
                    if res.get(temp_conf["general"]["client"]):
                        res[temp_conf["general"]["client"]][
                            temp_conf["uuid"]
                        ] = temp_conf["general"]["hostname"]
                    else:
                        res[temp_conf["general"]["client"]] = dict()
                        res[temp_conf["general"]["client"]][
                            temp_conf["uuid"]
                        ] = temp_conf["general"]["hostname"]
        return jsonify(res)
    except Exception as err:
        res = dict()
        res["error"] = str(err)
        return jsonify(res)


@app.route("/get_collecte", methods=["GET"])
def get_collecte_by_id():
    try:
        collecte_id = request.args.get("id")
        res = dict()
        res = _get_collecte_by_id(uuid=collecte_id)
        if "uuid" not in res:
            raise Exception("[get_collecte_by_id] No config file found")
        return jsonify(res)
    except Exception as err:
        res = dict()
        res["error"] = str(err)
        return jsonify(res)


def _get_collecte_by_id(uuid: str = "") -> dict:
    try:
        collecte_id = uuid
        res = dict()
        res["message"] = "Collecte not found"
        sub_folders = triageutils.list_directory(
            src=UPLOAD_FOLDER, onlydirs=True, LOGLEVEL="NOLOG"
        )
        for folder in sub_folders:
            if folder == collecte_id:
                _files = triageutils.list_directory(
                    src=os.path.join(UPLOAD_FOLDER, folder),
                    onlyfiles=True,
                    LOGLEVEL="NOLOG",
                )
                conf_file = None
                for _f in _files:
                    if _f == "config.yaml":
                        conf_file = os.path.join(UPLOAD_FOLDER, folder, _f)
                        break
                if conf_file:
                    res = triageutils.read_config(conf_file)
                    break
        check_config(conf=res)
        return res
    except Exception as err:
        res = generate_config()
        res["error"] = str(err)
        return res


def _close_collecte_by_id(uuid: str = "") -> dict:
    try:
        collecte_id = uuid
        res = dict()
        l = get_logger(name=collecte_id)
        config = _get_collecte_by_id(uuid=collecte_id)
        if "uuid" not in config:
            raise Exception("[close_collecte_by_id] No config file found")
        l.info("========================= CLOSE COLLECTE =========================")
        l.info("[close_collecte_by_id] Create ZIP from collecte...")
        triageutils.delete_directory(src=config["general"]["extracted_zip"], logger=l)
        triageutils.zip_folder(
            zip_path=config["general"]["extract"],
            zip_name=f'{config["general"]["client"]}#_#{config["general"]["hostname"]}',
            target_dir=f'{config["general"]["extract"]}/{config["general"]["hostname"]}',
            del_directory=False,
            logger=l,
        )
        res["status"] = "close collecte started"
        return res
    except Exception as err:
        res = dict()
        res["error"] = str(err)
        return res


def _open_collecte_by_id(uuid: str = "") -> dict:
    try:
        collecte_id = uuid
        res = dict()
        l = get_logger(name=collecte_id)
        l.info("========================= OPEN COLLECTE =========================")
        l.info("[open_collecte_by_id] Open Collecte...")
        zip_collectes = triageutils.list_directory(
            src=UPLOAD_FOLDER, onlyfiles=True, logger=l
        )
        zip_collecte = None
        for collecte in zip_collectes:
            if collecte.startswith(collecte_id):
                zip_collecte = os.path.join(UPLOAD_FOLDER, collecte)
                break
        if zip_collecte:
            extract_path = os.path.join(UPLOAD_FOLDER, collecte_id)
            triageutils.create_directory_path(path=extract_path, logger=l)
            triageutils.extract_zip_archive(
                archive=zip_collecte, dest=extract_path, logger=l
            )
            l.info("[open_collecte_by_id] Collecte ré-ouverte [OK]")
            if triageutils.delete_file(zip_collecte):
                l.info("[open_collecte_by_id] ZIP deleted [OK]")
            else:
                l.info("[open_collecte_by_id] ZIP deleted [NOK]")
        else:
            raise Exception(
                f"[open_collecte_by_id] No collecte found with uuid: {uuid}"
            )
        res["infos"] = "Collecte ré-ouverte [OK]"
        return res
    except Exception as err:
        res = dict()
        res["error"] = str(err)
        return res


@celery.task(name="start_triage")
def start_triage(config=None):
    try:
        if config:
            if not config.get("uuid", ""):
                raise Exception("UUID not set")
            l = get_logger(name=config["uuid"])
            config["task_id"] = start_triage.request.id
            l.info(f'[start_triage] Input: {config["uuid"]}')
            with open(os.path.join(config["path"], "config.yaml"), "w") as config_file:
                yaml.dump(config, config_file, sort_keys=False)
            try:
                errors_dict = dict()
                eps = generate_entry_points()
                for plugin_name, value in config["run"].items():
                    plugin = None
                    if type(value) is bool:
                        if value:
                            plugin = load_plugin(plugin_name, eps)
                    elif type(value) is dict:
                        if value["plugin"]:
                            plugin = load_plugin(plugin_name, eps)
                    if plugin:
                        l.info(f"[start_triage] RUN Plugin: {plugin_name}")
                        try:
                            p = plugin(conf=config)
                            p.run(logger=l)  # logger for decorator LOG
                            l.info(f"[start_triage] {plugin_name} : [OK]")
                        except Exception as ex:
                            errors_dict[plugin_name] = str(ex)
                            l.error(f"[start_triage] Plugin: {plugin_name} => {ex}")
                        finally:
                            l.info("[start_triage] Execute next plugin")
                l.info("[start_triage] End plugins")
                if config["general"]["auto_close_collecte"]:
                    l.info("[start_triage] Closing collecte")
                    _close_collecte_by_id(uuid=config["uuid"])
                for k, v in errors_dict.items():
                    l.error(f"[{k}] : {v}")
                l.info("[start_triage] END")
            except Exception as err:
                l.error(f"[start_triage plugins]: {err}")
            finally:
                config = None
                l.info("========================= END task =========================")
        else:
            raise Exception("Archive or Config or Path is None")
    except Exception as ex:
        l = get_logger(name="admin")
        l.error(f"[start_triage ERROR]: {ex}")


@app.route("/open_collecte_by_id", methods=["GET"])
def open_collecte_by_id(collecte_id: str = ""):
    try:
        if request.method == "GET":
            collecte_id = request.args.get("id")
        res = dict()
        l = get_logger(name=collecte_id)

        temp_col = dict()
        temp_col["client"] = "Open Collecte"
        temp_col["hostname"] = "N/A"
        temp_col["action"] = "open_collecte"
        temp_col["uuid"] = collecte_id

        res = _open_collecte_by_id(uuid=collecte_id)
        return jsonify(res)
    except Exception as err:
        res = dict()
        res["error"] = str(err)
        return jsonify(res)
    finally:
        l.info("========================= END task =========================")


@app.route("/download", methods=["GET"])
def download_collecte_by_id():
    try:
        collecte_id = request.args.get("id")
        res = dict()
        res = _get_collecte_by_id(uuid=collecte_id)
        if not res.get("uuid", ""):
            raise Exception("[download_collecte_by_id] No config file found")
        collecte_file = os.path.join(res["path"], res["archive"]["name"])

        if triageutils.file_exists(file=collecte_file, LOGLEVEL="NOLOG"):
            file_name = os.path.join(res["path"], res["archive"]["name"])
            return send_file(path_or_file=file_name, as_attachment=True)
        else:
            res = dict()
            res["error"] = "[download_collecte_by_id] File not found"
            return jsonify(res)
    except Exception as err:
        res = dict()
        res["error"] = str(err)
        return jsonify(res)


@app.route("/results/<string:uuid>", methods=["GET"])
def download_result_file(uuid: str):
    try:
        res = _get_collecte_by_id(uuid=uuid)
        if not res.get("uuid", ""):
            raise Exception("[download_result_file] No config file found")
        _path = os.path.join(
            res["general"]["extract"],
            f'{res["general"]["client"]}#_#{res["general"]["hostname"]}.zip',
        )
        if triageutils.file_exists(file=_path, LOGLEVEL="NOLOG"):
            return send_file(path_or_file=_path, as_attachment=True)
        else:
            res = dict()
            res["error"] = f"[download_result_file] File {_path} not found"
            return jsonify(res)
    except Exception as err:
        res = dict()
        res["error"] = str(err)
        return jsonify(res)


@app.route("/get_running_collectes", methods=["GET"])
def get_running_collectes():
    try:
        res = _get_running_collectes()
        return jsonify(res)
    except Exception as err:
        res = dict()
        res["error"] = str(err)
        return jsonify(res)


def _get_running_collectes():
    try:
        res = dict()
        _tasks = celery.control.inspect().active()
        res["running"] = list()
        for _values in _tasks.values():
            for _v in _values:
                _arg = _v.get("args", [])[0]
                if _arg:
                    _client = _arg.get("general", {}).get("client", "")
                    _hostname = _arg.get("general", {}).get("hostname", "")
                    _task_id = _arg.get("task_id", "")
                    _uuid = _arg.get("uuid", "")
                    res["running"].append(
                        {
                            "client": _client,
                            "hostname": _hostname,
                            "uuid": _uuid,
                            "task_id": _task_id,
                        }
                    )
        return res
    except Exception as err:
        res = dict()
        res["error"] = str(err)
        return res


@app.route("/get_collecte_status", methods=["GET"])
def get_collecte_status():
    try:
        task_id = request.args.get("task_id")
        task_result = AsyncResult(task_id)
        return jsonify(
            {
                "task_id": task_id,
                "task_status": task_result.status,
                "task_state": task_result.state,
                "task_result": task_result.result,
            }
        )
    except Exception as err:
        res = dict()
        res["error"] = str(err)
        return jsonify(res)


def _get_collecte_status(task_id: str):
    try:
        task_result = AsyncResult(task_id)
        return dict(
            {
                "task_id": task_id,
                "task_status": task_result.status,
                "task_state": task_result.state,
                "task_result": task_result.result,
                "error": "",
            }
        )
    except Exception as err:
        return dict(
            {
                "task_id": task_id,
                "task_status": "",
                "task_state": "",
                "task_result": "",
                "error": str(err),
            }
        )


@app.route("/process", methods=["POST"])
def process(collecte_id: str = ""):
    try:
        if request.method == "POST":
            collecte_id = request.json["uuid"] if request.json.get("uuid") else "None"
        res = dict()
        res = _get_collecte_by_id(uuid=collecte_id)
        if not res.get("uuid", ""):
            raise Exception("No config file found for given ID")
        l = get_logger(name=collecte_id)
        l.info("========================= START task =========================")
        task = start_triage.delay(res)
        return jsonify(uuid=collecte_id, task_id=task.id)
    except Exception as ex:
        return jsonify(error=f"[process] {str(ex)}")


@app.route("/admincollectes", methods=["GET"])
def admin_get_collectes():
    try:
        cols = _get_admin_collectes()
        return jsonify(cols)
    except Exception as ex:
        return jsonify(error=f"[get_admin_collectes] {str(ex)}")


@app.route("/admindeletecollecte", methods=["POST"])
def admin_delete_collectes():
    try:
        admin_logger = get_logger(name="admin")
        uuid = None
        if request.method == "POST":
            uuid = request.json["uuid"] if request.json.get("uuid") else None
            state = request.json["state"] if request.json.get("state") else "None"
            client = request.json["client"] if request.json.get("client") else "None"
            hostname = (
                request.json["hostname"] if request.json.get("hostname") else "None"
            )
        if uuid:
            _running_col = _get_running_collectes()
            res = "Collecte is running and cannot be deleted"
            _del = True
            for _run in _running_col.get("running", []):
                if _run.get("uuid", "") == uuid:
                    _del = False
                    break
            if _del:
                path = os.path.join(UPLOAD_FOLDER, uuid)
                if triageutils.delete_directory(src=path, logger=admin_logger):
                    res = "Collecte deleted successfully"
                else:
                    res = "Collecte not deleted error"
                triageutils.delete_file(
                    src=os.path.join(LOG_FOLDER, f"{uuid}.log"),
                    logger=admin_logger,
                )
        else:
            res = "Error on collecte's uuid"
        return jsonify(status=res)
    except Exception as ex:
        return jsonify(status=f"[admin_delete_collectes] {str(ex)}")


def _get_admin_collectes():
    try:
        res = dict()
        sub_folders = triageutils.list_directory(
            src=UPLOAD_FOLDER, onlydirs=True, LOGLEVEL="NOLOG"
        )
        for folder in sub_folders:
            if len(folder.split("-")) == 5:
                _files = triageutils.list_directory(
                    src=os.path.join(UPLOAD_FOLDER, folder),
                    onlyfiles=True,
                    LOGLEVEL="NOLOG",
                )
                conf_file = None
                for _f in _files:
                    if _f == "config.yaml":
                        conf_file = os.path.join(UPLOAD_FOLDER, folder, _f)
                        break
                if conf_file:
                    temp_conf = triageutils.read_config(conf_file)
                    uuid = temp_conf["uuid"]
                    hostname = temp_conf["general"]["hostname"]
                    client = temp_conf["general"]["client"]
                    _mtime = os.path.getmtime(conf_file)
                    mtime = datetime.fromtimestamp(_mtime).strftime("%d/%m/%Y")
                    _state = _get_collecte_status(temp_conf["task_id"])
                    res[uuid] = {
                        "client": client,
                        "hostname": hostname,
                        "uuid": uuid,
                        "state": _state.get("task_status"),
                        "mtime": mtime,
                    }

        return res
    except Exception as err:
        res = dict()
        res["error"] = str(err)
        return res


@app.route("/admintimesketchstatus", methods=["GET"])
def admin_get_ts_status():
    try:
        _ts = admin_utils.is_timesketch_connected()
        return jsonify(status=_ts)
    except Exception as ex:
        return jsonify(status=False, error=f"[admin_get_ts_status] {str(ex)}")


@app.route("/admintimesketchlistsketchs", methods=["GET"])
def admin_get_all_sketchs():
    try:
        _AllSketchs = admin_utils.get_all_sketchs()
        _parsed_sketchs = list()
        for _s in _AllSketchs:
            _parsed_sketchs.append({"id": _s.id, "Name": _s.name})
        return jsonify(sketchs=_parsed_sketchs)
    except Exception as ex:
        return jsonify(sketchs={}, error=f"[admin_get_all_sketchs] {str(ex)}")


@app.route("/adminelasticstatus", methods=["GET"])
def admin_get_elastic_status():
    try:
        _elastic = admin_utils.is_elastic_connected()
        return jsonify(status=_elastic)
    except Exception as ex:
        return jsonify(status=False, error=f"[admin_get_elastic_status] {str(ex)}")


@app.route("/adminelasticlistindices", methods=["GET"])
def admin_get_all_indices():
    try:
        _AllIndices = admin_utils.get_all_indices()
        _parsed_indices = list()
        for _i in _AllIndices:
            _parsed_indices.append({"Name": _i})
        return jsonify(clients_indices=_parsed_indices)
    except Exception as ex:
        return jsonify(clients_indices={}, error=f"[admin_get_all_index] {str(ex)}")


@app.route("/admindeletesketch", methods=["POST"])
def admin_delete_sketch(id: int = 0):
    try:
        if request.method == "POST":
            id = request.json["id"] if int(request.json.get("id")) else 0
        res = admin_utils.delete_sketch_by_id(id=id)
        return jsonify(status=res)
    except Exception as ex:
        return jsonify(status=False, error=f"[admin_delete_sketch] {str(ex)}")


@app.route("/admindeleteindice", methods=["POST"])
def admin_delete_indice():
    try:
        if request.method == "POST":
            name = request.json["name"] if str(request.json.get("name")) else None
            if name:
                res = admin_utils.delete_indice_by_name(indice_name=name)
                return jsonify(status=res)
            else:
                return jsonify(
                    status=False, error="[admin_delete_indice] Missing name data"
                )
        else:
            return jsonify(
                status=False, error="[admin_delete_indice] Not a POST request"
            )
    except Exception as ex:
        return jsonify(status=False, error=f"[admin_delete_indice] {str(ex)}")


@app.route("/adminhayabusaversion", methods=["GET"])
def admin_get_hayabusa_version():
    try:
        _hv = admin_utils.get_hayabusa_version()
        return jsonify(version=_hv)
    except Exception as ex:
        return jsonify(version="0.0.0", error=f"[admin_get_hayabusa_version] {str(ex)}")


@app.route("/admin_upload_hayabusa", methods=["POST"])
def admin_upload_hayabusa():
    try:
        _hv = True
        try:
            uploaded_file = request.files["archive"]
            filename = secure_filename(uploaded_file.filename)
            uploaded_file.save(os.path.join(UPLOAD_FOLDER, filename))
            sha256 = hashlib.sha256()
            with open(os.path.join(UPLOAD_FOLDER, filename), "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256.update(byte_block)
            file_sha256 = sha256.hexdigest()
        except Exception as file_error:
            filename = "ERROR_filename"
            file_sha256 = "ERROR_SHA"
            _hv = False
            return jsonify(status=_hv, error=f"Upload file error: {file_error}")
        _hv = admin_utils.update_hayabusa(
            zip_file=os.path.join(UPLOAD_FOLDER, filename)
        )
        return jsonify(status=_hv)
    except Exception as ex:
        return jsonify(status=False, error=f"[admin_upload_hayabusa] {str(ex)}")


@app.route("/admin_get_logstash_connections", methods=["GET"])
def admin_get_logstash_connections():
    try:
        _logstash_ip = INTERNAL_CONFIG["general"]["logstash_url"]
        _logstash_ports = [(k, v) for k, v in INTERNAL_CONFIG["pipelines"].items()]
        _conns = []
        for _service, _port in _logstash_ports:
            _temp = dict()
            _temp["service"] = _service
            _temp["port"] = _port
            _temp["status"] = admin_utils.check_connection(ip=_logstash_ip, port=_port)
            _conns.append(_temp)
        return jsonify(connections=_conns)
    except Exception as ex:
        return jsonify(
            connections=[], error=f"[admin_get_logstash_connections] {str(ex)}"
        )


def check_internal_config(conf: dict = {}) -> None:
    try:
        for k, v in recursive_items(conf):
            if k and not v:
                raise Exception(
                    f"[check_internal_config] Missing value for {k} in config file"
                )
    except Exception as err:
        raise err


def main():
    print("======= Running on https://0.0.0.0 =======")
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(
        "config/certs/pytriage.crt", "config/certs/pytriage.key"
    )
    app.config["JSON_SORT_KEYS"] = False
    app.static_url_path = "src/web/static"
    app.static_folder = (
        "src/web/static"  # os.path.join(app.root_path, app.static_url_path)
    )
    app.template_folder = "src/web/templates"
    app.logger.disabled = True
    log = logging.getLogger("werkzeug")
    log.disabled = True
    log = logging.getLogger("asyncio")
    log.setLevel(logging.WARNING)

    app.run(host="0.0.0.0", port=8080, debug=True, ssl_context=ssl_context)


if __name__ == "__main__":
    try:
        check_internal_config(conf=INTERNAL_CONFIG)
        main()
    except Exception as ex:
        print(f"[main function] ERROR: {str(ex)}")
        pass
