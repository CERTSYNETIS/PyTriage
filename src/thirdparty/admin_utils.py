import os
import stat
from elasticsearch import Elasticsearch
import socket
from timesketch_api_client import client
from .logging import get_logger
from .triageutils import (
    list_directory,
    zip_folder,
    extract_zip_archive,
    copy_directory,
    copy_file,
    move_file,
    delete_directory,
    delete_file,
    delete_files_in_directory,
    INTERNAL_CONFIG,
)

UPLOAD_FOLDER = INTERNAL_CONFIG["general"]["upload"]  # /data"
LOGGER = get_logger(name="admin")


# Logging decorator for all functions
def LOG(f):
    def wrapper(*args, **kwargs):
        p_args = str(kwargs) if len(str(kwargs)) < 300 else f"{str(kwargs)[0:300]}...}}"
        LOGGER.info(f"[CALLED] {f.__name__}: {p_args}")
        return f(*args, **kwargs)

    return wrapper


@LOG
def is_timesketch_connected() -> bool:
    """Check if TS is online

    Args:

    Returns:
        Bool
    """
    # config file on triage /home/triage/.timesketchrc
    try:
        if not INTERNAL_CONFIG["administration"]["Timesketch"]["active"]:
            return False
        host_uri = INTERNAL_CONFIG["administration"]["Timesketch"]["url"]
        username = INTERNAL_CONFIG["administration"]["Timesketch"]["username"]
        password = INTERNAL_CONFIG["administration"]["Timesketch"]["password"]
        ts = client.TimesketchApi(
            host_uri=host_uri,
            username=username,
            password=password,
            verify=False,
            auth_mode="userpass",
        )
        # ts = config.get_client(config_section="timesketch")
        if ts:
            if next(ts.list_sketches()):
                LOGGER.info("[get_timesketch_status] Connection OK")
                return True
            else:
                LOGGER.error("[get_timesketch_status] No sketch")
                return False
        else:
            LOGGER.error("[get_timesketch_status] TS is NONE")
            return False
    except Exception as ex:
        # error "format code..." is in importer.py
        LOGGER.error(f"[get_timesketch_status] {str(ex)}")
        return False


@LOG
def is_elastic_connected() -> bool:
    """Check if Elastic is online

    Args:

    Returns:
        Bool
    """
    try:
        if not INTERNAL_CONFIG["administration"]["Elastic"]["active"]:
            return False
        host_uri = INTERNAL_CONFIG["administration"]["Elastic"]["url"]
        port = INTERNAL_CONFIG["administration"]["Elastic"]["port"]
        username = INTERNAL_CONFIG["administration"]["Elastic"]["username"]
        password = INTERNAL_CONFIG["administration"]["Elastic"]["password"]

        es = Elasticsearch(
            f"{host_uri}:{port}", basic_auth=(username, password), verify_certs=False
        )

        if es.ping():
            LOGGER.info("[is_elastic_connected] Connection OK")
            return True
        else:
            LOGGER.error("[is_elastic_connected] Connection NOK")
            return False
    except Exception as ex:
        LOGGER.error(f"[is_elastic_connected] {str(ex)}")
        return False


@LOG
def delete_sketch_by_id(id: int = 0) -> bool:
    """Delete sketch from TS

    Args:
        int: sketch id
    Returns:
        Bool
    """
    # config file on triage /home/triage/.timesketchrc
    try:
        _res = True
        if not INTERNAL_CONFIG["administration"]["Timesketch"]["active"]:
            raise Exception("Module Timesketch not active")
        host_uri = INTERNAL_CONFIG["administration"]["Timesketch"]["url"]
        username = INTERNAL_CONFIG["administration"]["Timesketch"]["username"]
        password = INTERNAL_CONFIG["administration"]["Timesketch"]["password"]
        ts = client.TimesketchApi(
            host_uri=host_uri,
            username=username,
            password=password,
            verify=False,
            auth_mode="userpass",
        )
        if ts:
            ## delete sketch
            sketch = ts.get_sketch(sketch_id=id)
            if sketch:
                _timelines = sketch.list_timelines()
                for _t in _timelines:
                    LOGGER.info(f"[delete_sketch_by_id] index_name {_t.index_name} ")
                    _i = _t.index
                    _res &= _t.delete()
                    if not _res:
                        raise Exception("unable to delete timeline")
                    LOGGER.info(f"[delete_sketch_by_id] Delete timeline {_res} ")
                    _res &= _i.delete()
                    if not _res:
                        raise Exception("unable to delete index")
                    LOGGER.info(f"[delete_sketch_by_id] Delete index {_res} ")
                _res &= sketch.delete()
                LOGGER.info(f"[delete_sketch_by_id] Delete sketch {_res} ")
                return _res
        else:
            LOGGER.error("[delete_sketch_by_id] TS is NONE")
            return False
    except Exception as ex:
        LOGGER.error(f"[delete_sketch_by_id] {str(ex)}")
        return False


@LOG
def delete_indice_by_name(indice_name: str) -> bool:
    """Delete indice from Elastic

    Args:
        int: indices name
    Returns:
        Bool
    """
    try:
        if not INTERNAL_CONFIG["administration"]["Elastic"]["active"]:
            raise Exception("Module Eslactic not active")
        host_uri = INTERNAL_CONFIG["administration"]["Elastic"]["url"]
        port = INTERNAL_CONFIG["administration"]["Elastic"]["port"]
        username = INTERNAL_CONFIG["administration"]["Elastic"]["username"]
        password = INTERNAL_CONFIG["administration"]["Elastic"]["password"]

        _res = True
        es = Elasticsearch(
            f"{host_uri}:{port}", basic_auth=(username, password), verify_certs=False
        )

        if es.ping():
            indices = get_all_indices()
            if indice_name in indices:
                indices_response = es.indices.get(index=f"{indice_name}*")
                LOGGER.info(
                    f"[delete_indice_by_name] Delete indice with the pattern : {indice_name}*"
                )
                for indice in indices_response:
                    LOGGER.info(f"[delete_indice_by_name] Indice {indice}")
                    _res &= (es.indices.delete(index=indice))["acknowledged"]
                    LOGGER.info(f"[delete_indice_by_name] Delete indice {_res}")
                return _res
            else:
                LOGGER.error("[delete_indice_by_name] Indice doesn't exist")
                return False
        else:
            LOGGER.error("[delete_indice_by_name] Connection NOK")
            return False
    except Exception as ex:
        LOGGER.error(f"[delete_indice_by_name] {str(ex)}")
        return False


@LOG
def get_all_indices() -> list:
    try:
        if not INTERNAL_CONFIG["administration"]["Elastic"]["active"]:
            raise Exception("Module Eslactic not active")
        host_uri = INTERNAL_CONFIG["administration"]["Elastic"]["url"]
        port = INTERNAL_CONFIG["administration"]["Elastic"]["port"]
        username = INTERNAL_CONFIG["administration"]["Elastic"]["username"]
        password = INTERNAL_CONFIG["administration"]["Elastic"]["password"]

        es = Elasticsearch(
            f"{host_uri}:{port}", basic_auth=(username, password), verify_certs=False
        )
        clients_indices = list()

        if es.ping():
            patterns = [
                "ir-lin-*",
                "ir-orc-*",
                "ir-m365-*",
                "ir-ad-*",
                "secop-ad-*",
                "ir-log-*",
                "dlq-*",
                "ir-evtx-*",
            ]

            for pattern in patterns:
                indices_response = es.indices.get(index=pattern)
                for i in indices_response:
                    last_dash = i.rfind("-")
                    client_name = i[:last_dash]
                    if i != "ir-log-assessment-indexing":
                        if client_name not in clients_indices:
                            clients_indices.append(client_name)
            return clients_indices
        else:
            LOGGER.error("[get_all_indices] es is NONE")
            return []
    except Exception as ex:
        LOGGER.error(f"[get_all_indices] {str(ex)}")
        return []


@LOG
def get_all_sketchs() -> list:
    """Get all sketchs from TS

    Args:

    Returns:
        List of sketch
    """
    # config file on triage /home/triage/.timesketchrc
    try:
        if not INTERNAL_CONFIG["administration"]["Timesketch"]["active"]:
            return list()
        host_uri = INTERNAL_CONFIG["administration"]["Timesketch"]["url"]
        username = INTERNAL_CONFIG["administration"]["Timesketch"]["username"]
        password = INTERNAL_CONFIG["administration"]["Timesketch"]["password"]
        ts = client.TimesketchApi(
            host_uri=host_uri,
            username=username,
            password=password,
            verify=False,
            auth_mode="userpass",
        )
        if ts:
            ## list sketch
            _my_sketchs = list(ts.list_sketches())
            _my_sketchs.extend(list(ts.list_sketches(scope="shared")))
            return _my_sketchs
        else:
            LOGGER.error("[get_all_sketchs] TS is NONE")
            return list()
    except Exception as ex:
        # error "format code..." is in importer.py
        LOGGER.error(f"[get_all_sketchs] {str(ex)}")
        return list()


@LOG
def get_hayabusa_version() -> str:
    try:
        files = list_directory(src="/hayabusa", onlyfiles=True, logger=LOGGER)
        _v = "0.0.0"
        for _f in files:
            if "hayabusa" in _f and "-" in _f:
                _v = _f.split("-")[1]
                break
        return _v
    except Exception as ex:
        LOGGER.error(f"[get_hayabusa_version] {str(ex)}")
        return "0.0.0"


@LOG
def update_hayabusa(zip_file="") -> bool:
    try:
        _version = get_hayabusa_version()
        LOGGER.info(f"[update_hayabusa] Version: {_version}")
        _extracted_path = os.path.join(UPLOAD_FOLDER, "hayabusa_temp")
        _hayabusa_path = "/hayabusa"

        try:
            extract_zip_archive(archive=zip_file, dest=_extracted_path, logger=LOGGER)
        except Exception as e1:
            LOGGER.error(f"[update_hayabusa] Extract ZIP: {str(e1)}")
            return False
        try:
            zip_folder(
                zip_path=UPLOAD_FOLDER,
                zip_name=f"hayabusa_{_version}_backup",
                target_dir=_hayabusa_path,
                del_directory=False,
                logger=LOGGER,
            )
            delete_files_in_directory(src=_hayabusa_path, logger=LOGGER)
        except Exception as e2:
            LOGGER.error(f"[update_hayabusa] Zip folder: {str(e2)}")
            return False
        try:
            copy_directory(src=_extracted_path, dst=_hayabusa_path, logger=LOGGER)
        except Exception as e3:
            LOGGER.error(f"[update_hayabusa] Copy directory: {str(e3)}")
            return False
        try:
            _exec_file = ""
            _hayabusa_path_files = list_directory(
                src=_hayabusa_path, onlyfiles=True, logger=LOGGER
            )
            for _f in _hayabusa_path_files:
                if _f.endswith("-musl"):
                    _exec_file = os.path.join(_hayabusa_path, _f)
                    copy_file(
                        src=_exec_file,
                        dst=_hayabusa_path,
                        overwrite=False,
                        logger=LOGGER,
                    )
            _res = chmod_file(file_path=_exec_file, mode=stat.S_IEXEC)
            LOGGER.info(f"[update_hayabusa] chmod result: {_res}")
            move_file(
                src=_exec_file,
                dst=os.path.join(_hayabusa_path, "hayabusa"),
                logger=LOGGER,
            )
        except Exception as e4:
            LOGGER.error(f"[update_hayabusa] chmod file: {str(e4)}")
            return False
        try:
            delete_directory(src=_extracted_path, logger=LOGGER)
            delete_file(src=zip_file, logger=LOGGER)
        except Exception as e5:
            LOGGER.error(f"[update_hayabusa] Delete temp directory: {str(e5)}")
            return False
        return True
    except Exception as ex:
        LOGGER.error(f"[update_hayabusa] {str(ex)}")
        return False


@LOG
def chmod_file(file_path: str = "", mode: int = 0) -> bool:
    try:
        if not mode:
            LOGGER.error("[chmod_file] mode is None")
            return False
        st = os.stat(file_path)
        os.chmod(file_path, st.st_mode | mode)
        return True
    except Exception as ex:
        LOGGER.error(f"[chmod_file] {str(ex)}")
        return False


@LOG
def check_connection(ip: str = "elk.cert.lan", port: int = 0) -> bool:
    try:
        if ip.startswith("http"):
            ip = ip.split("//")[1]
        LOGGER.info(f"[check_connection] {ip}:{port}")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, port))
        sock.close()
        return True
    except Exception as ex:
        if sock:
            sock.close()
        LOGGER.error(f"[check_connection] {str(ex)}")
        return False
