import os
import shutil
import logging
import tarfile
import chardet
import socket
import json
import csv
import yaml
import time
import types
import gzip
import subprocess
from typing import Optional
import re
import py7zr
from charset_normalizer import detect
from pathlib import Path
import zipfile_deflate64 as zipfile
from timesketch_api_client import client
from timesketch_import_client import importer
from datetime import datetime
from .orc_decrypt import decrypt_archive
from .logging import get_logger

magics = {
    ".gzip": [b"\x1f\x8b"],
    ".tar": [b"\x1f\xa0", b"\x1f\x9d", b"\x75\x73\x74\x61\x72"],
    ".zip": [b"\x50\x4b\x03\x04", b"\x50\x4b\x05\x06", b"\x50\x4b\07\x08"],
    ".7z": [b"\x37\x7a\xbc\xaf\x27\x1c"],
    ".gz": [b"\x1f\x8b"],
    ".xz": [b"\xfd\x37\x7a\x58\x5a\x00"],
    ".lzip": [b"\x4c\x5a\x49\x50"],
    ".rar": [b"\x52\x61\x72\x21\x1a\x07"],
}


def set_default_logger():
    l = get_logger(name="default")
    return l


LOGGER = set_default_logger()


def read_config(conf="") -> dict:
    """Lecture du fichier de configuration

    Args:
        conf (str): chemin du fichier yaml
    Returns:
        un dictionnaire contenant les informations du yaml
    """
    with open(conf, "r") as stream:
        try:
            d = yaml.safe_load(stream)
            return d
        except yaml.YAMLError as ex:
            raise (ex)


INTERNAL_CONFIG = read_config(os.path.join("config", "triage.yaml"))


def set_logger(logger=LOGGER):
    global LOGGER
    LOGGER = logger


# Logging decorator for all functions
def LOG(f):
    def wrapper(*args, **kwargs):
        nolog = False
        for k, v in kwargs.items():
            if k == "LOGLEVEL" and v == "NOLOG":
                nolog = True
            elif k == "logger" or type(v) is logging.Logger:
                set_logger(v)
        if LOGGER:
            if nolog:
                return f(*args, **kwargs)
            p_args = (
                str(kwargs) if len(str(kwargs)) < 300 else f"{str(kwargs)[0:300]}...}}"
            ).replace("<Logger", "")
            LOGGER.info(f"[CALLED] {f.__name__}: {p_args}")
        # LOGGER.error(f"[CALLED] {f.__name__}: {kwargs}")
        return f(*args, **kwargs)

    return wrapper


@LOG
def copy_file(
    src: str | Path = "",
    dst: str | Path = "",
    overwrite: bool = False,
    LOGLEVEL: str = "INFO",
    logger=LOGGER,
):
    """
    Copy file (src) to directory (dst)
    """
    if not directory_exists(dir=dst, logger=logger):
        create_directory_path(path=dst, logger=logger)
    if not overwrite:
        t_file = f"{dst}/{src.split('/')[-1]}"
        if file_exists(file=t_file):
            n_file = f"{str(time.time()).split('.')[0]}_{src.split('/')[-1]}"
            dst = f"{dst}/{n_file}"
            logger.info(f"[copy_file] File already exists, renamed: {n_file}")
    return shutil.copy2(src, dst)


@LOG
def copy_file_strict(
    src: Path,
    dst: Path,
    LOGLEVEL: str = "INFO",
    logger=LOGGER,
):
    """
    Copy file(src) to file (dst)
    """
    return shutil.copy2(src, dst)


@LOG
def copy_directory(
    src: str | Path = "", dst: str | Path = "", LOGLEVEL: str = "INFO", logger=LOGGER
) -> str | Path:
    return shutil.copytree(src=src, dst=dst, dirs_exist_ok=True)


@LOG
def list_subdirectories(src: str = "", LOGLEVEL: str = "INFO", logger=LOGGER) -> list:
    return [x[0] for x in os.walk(src)]


@LOG
def list_directory(
    src: str = "",
    onlyfiles: bool = False,
    onlydirs: bool = False,
    LOGLEVEL: str = "INFO",
    logger=LOGGER,
) -> list:
    """
    return list of elements in folder without path
    """
    if onlydirs:
        return [
            name for name in os.listdir(src) if os.path.isdir(os.path.join(src, name))
        ]
    elif onlyfiles:
        return [
            name for name in os.listdir(src) if os.path.isfile(os.path.join(src, name))
        ]
    else:
        return [name for name in os.listdir(src)]


@LOG
def list_directory_full_path(
    src: str | Path = "",
    onlyfiles: bool = False,
    onlydirs: bool = False,
    LOGLEVEL: str = "INFO",
    logger=LOGGER,
) -> list:
    """
    return list of elements with absolute path
    """
    if onlydirs:
        return [
            os.path.join(src, name)
            for name in os.listdir(src)
            if os.path.isdir(os.path.join(src, name))
        ]
    elif onlyfiles:
        return [
            os.path.join(src, name)
            for name in os.listdir(src)
            if os.path.isfile(os.path.join(src, name))
        ]
    else:
        return [os.path.join(src, name) for name in os.listdir(src)]


@LOG
def move_file(
    src: str = "",
    dst: str = "",
    check_dir: bool = False,
    LOGLEVEL: str = "INFO",
    logger=LOGGER,
):
    if check_dir:
        if not directory_exists(dir=dst, logger=logger):
            create_directory_path(path=dst, logger=logger)
    return shutil.move(src, dst)


@LOG
def copy_files(
    src: list = [],
    dst: str | Path = "",
    overwrite: bool = False,
    LOGLEVEL: str = "INFO",
    logger=LOGGER,
):
    result = True
    for f in src:
        try:
            copy_file(src=f, dst=dst, overwrite=overwrite, logger=logger)
        except Exception as ex:
            logger.error(f"[copy_files ERROR] {ex}")
            result = False
    return result


@LOG
def delete_directory(
    src: str | Path = "", LOGLEVEL: str = "INFO", logger=LOGGER
) -> bool:
    try:
        if directory_exists(dir=src, logger=logger):
            shutil.rmtree(src)
            return True
        else:
            logger.error("Directory does not exist")
            return False
    except Exception as ex:
        logger.error(f"[delete_directory] {str(ex)}")
        return False


@LOG
def delete_file(src: str | Path = "", LOGLEVEL: str = "INFO", logger=LOGGER) -> bool:
    try:
        if os.path.exists(src):
            os.remove(src)
            return True
        logger.error(f"[delete_file] Path {src} does not exist")
        return False
    except Exception as ex:
        logger.error(f"[delete_file] {str(ex)}")
        return False


@LOG
def delete_files_in_directory(
    src: str = "", files_to_save: list = [], LOGLEVEL: str = "INFO", logger=LOGGER
) -> bool:
    try:
        if directory_exists(dir=src, logger=logger):
            for file in list_directory_full_path(src=src, logger=logger):
                if os.path.isdir(file):
                    delete_directory(src=file, logger=logger)
                elif os.path.isfile(file):
                    if file not in files_to_save:
                        if os.path.exists(file):
                            os.remove(file)
            return True
        else:
            logger.error("Directory does not exist")
            return False
    except Exception as ex:
        logger.error(f"[delete_directory] {str(ex)}")
        return False


@LOG
def create_directory_path(path: str | Path = "", LOGLEVEL: str = "INFO", logger=LOGGER):
    try:
        Path(path).mkdir(parents=True, exist_ok=True)
        return True
    except Exception as ex:
        logger.error(str(ex))
        return False


@LOG
def file_exists(file: str | Path = "", LOGLEVEL: str = "INFO", logger=LOGGER) -> bool:
    try:
        if Path(file).is_file():
            return True
        else:
            return False
    except Exception as ex:
        logger.error(str(ex))
        return False


@LOG
def directory_exists(dir: str = "", LOGLEVEL: str = "INFO", logger=LOGGER) -> bool:
    try:
        if Path(dir).is_dir():
            return True
        else:
            return False
    except Exception as ex:
        logger.error(f"[directory_exists ERROR] {str(ex)}")
        return False


@LOG
def search_files(
    src: str | Path = "",
    pattern: str = "",
    patterninpath: str = "",
    strict: bool = False,
    LOGLEVEL: str = "INFO",
    logger=LOGGER,
) -> list:
    """
    Cherche tous les fichiers récursivement selon un pattern sur le nom du fichier et/ou un pattern sur le nom du path.

    Args:
        dir (str): Dossier de recherche
        pattern (str): optionnel chaine de caractère à trouver dans le nom du fichier (ex: ".txt", "access"...)
        patterninpath (str): optionnel chaine de caractère à trouver dans le chemin du fichier (ex: "/var/log", "c:/users"...)
        strict (bool): optionnel le nom du fichier est identique au pattern

    Return:
        List : Full path of files found
    """
    records = []
    obj = os.walk(src)
    for dir_path, dir_names, file_names in obj:
        for file in file_names:
            if strict:
                if pattern == file:
                    records.append(os.path.join(dir_path, file))
            else:
                if patterninpath is not None:
                    if patterninpath in dir_path:
                        if pattern is not None:
                            if pattern in file:
                                records.append(os.path.join(dir_path, file))
                        else:
                            records.append(os.path.join(dir_path, file))
                elif pattern is not None:
                    if pattern in file:
                        records.append(os.path.join(dir_path, file))
    return records


@LOG
def search_files_generator(
    src: str | Path = "",
    pattern: str = "",
    patterninpath: str = "",
    strict: bool = False,
    logger=LOGGER,
):
    """Cherche tous les fichiers récursivement selon un pattern sur le nom du fichier et/ou un pattern sur le nom du path.
    Args:
        dir (str): Dossier de recherche
        pattern (str): optionnel chaine de caractère à trouver dans le nom du fichier (ex: ".txt", "access"...)
        patterninpath (str): optionnel chaine de caractère à trouver dans le chemin du fichier (ex: "/var/log", "c:/users"...)
        strict (bool): optionnel le nom du fichier est identique au pattern
    Return:
        Path : full path of found file
    """
    records = []
    obj = os.walk(src)
    for dir_path, dir_names, file_names in obj:
        for file in file_names:
            if strict:
                if pattern == file:
                    yield Path(os.path.join(dir_path, file))
            else:
                if patterninpath is not None:
                    if patterninpath in dir_path:
                        if pattern is not None:
                            if pattern == file and strict:
                                yield Path(os.path.join(dir_path, file))
                            elif pattern in file:
                                yield Path(os.path.join(dir_path, file))
                        else:
                            yield Path(os.path.join(dir_path, file))
                elif pattern is not None:
                    if pattern in file:
                        yield Path(os.path.join(dir_path, file))


@LOG
def search_files_by_extension_generator(
    src: str | Path,
    extension: str,
    patterninpath: str = "",
    logger=LOGGER,
):
    """Cherche tous les fichiers récursivement selon un pattern sur le nom du fichier et/ou un pattern sur le nom du path.
    Args:
        dir (str): Dossier de recherche
        extention (str):  extention des fichiers
        patterninpath (str): optionnel chaine de caractère à trouver dans le chemin du fichier (ex: "/var/log", "c:/users"...)
        strict (bool): optionnel le nom du fichier est identique au pattern

    Return:
        Path : full path of found file
    """
    records = []
    obj = os.walk(src)
    for dir_path, dir_names, file_names in obj:
        for file in file_names:
            if patterninpath:
                if patterninpath.lower() in dir_path.lower():
                    if file.endswith(extension):
                        yield Path(os.path.join(dir_path, file))
            elif file.endswith(extension):
                yield Path(os.path.join(dir_path, file))


@LOG
def get_folder_path_by_name(
    folder_name: str | Path,
    root: str | Path,
    LOGLEVEL: str = "INFO",
    logger=LOGGER,
) -> Path:
    """Cherche si un dossier existe et retourne son chemin.
    Args:
        folder_name (str): Nom du dossier à rechercher
        root (str): Où démarrer la recherche
    """
    for path, dirs, _ in os.walk(root):
        if folder_name in dirs:
            return Path(os.path.join(path, folder_name))
    return None


@LOG
def search_files_by_extension(
    dir: str | Path = "",
    extension: str = "",
    LOGLEVEL: str = "INFO",
    logger=LOGGER,
) -> list:
    """Cherche tous les fichiers récursivement selon une extention
    Args:
        dir (str): Dossier de recherche
        extension (str): optionnel chaine de caractère à trouver dans le nom du fichier (ex: ".txt", "access"...)
    Return:
        List[str] : Full path of found files
    """
    records = []
    obj = os.walk(dir)
    for dir_path, dir_names, file_names in obj:
        for file in file_names:
            if file.endswith(extension):
                records.append(os.path.join(dir_path, file))
    return records


@LOG
def get_file_in_list(
    list: list = [], patterns: list = [], LOGLEVEL: str = "INFO", logger=LOGGER
) -> Optional[str]:
    if list:
        for name in list:
            for p in patterns:
                if name.lower().endswith(p):
                    return name
    return None


@LOG
def extract_tar_archive(
    archive: str = "",
    dest: str = "",
    specific_files: list = [],
    LOGLEVEL: str = "INFO",
    logger=LOGGER,
):
    """Extrait tous les fichiers de l'archive TAR contenant les résultats uac.

    Args:
        archive (str): optionnel chemin complet du fichier tar
        dest (str): optionnel chemin complet de décompression de l'archive
        specific_files (tab): optionnel tableau avec le nom de fichier spécifiques à extraire
    """
    ret = None
    if not archive or not dest:
        logger.error("[extract_tar_archive] Args missing")
        raise Exception("[extract_tar_archive] Args missing")
    if tarfile.is_tarfile(archive):
        f_path = archive
        if archive.endswith("tar.gz"):
            _archive = tarfile.open(archive, "r:gz")
        elif archive.endswith("tar"):
            _archive = tarfile.open(archive, "r:")
        else:
            logger.error("[extract_tar_archive] Not a valid TAR")
            raise Exception("[extract_tar_archive] Not a valid TAR")
        ret = archive
        names = _archive.getnames()
        logger.info(f"[extract_tar_archive] nb of files: {len(names)}")
        if names and specific_files:
            for name in names:
                for i in range(len(specific_files)):
                    if specific_files[i] in name:
                        specific_files[i] = name
        try:
            if len(specific_files) > 0:
                for f in specific_files:
                    _archive.extract(f, path=dest)
            else:
                _archive.extractall(path=dest)
            _archive.close()

        except Exception as ex:
            logger.error(f"[extract_tar_archive] {str(ex)}")
            logger.info("[extract_tar_archive] Exec tar command...")
            p = subprocess.Popen(
                ["tar", "-C", dest, "-xvf", f_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                env=os.environ,
            )
            (output, err) = p.communicate()
            p_status = p.wait()
            logger.info(f"[extract_tar_archive] tar status: {p_status} / error: {err}")
            # raise ex
        return ret
    else:
        logger.error("[extract_tar_archive] Not a valid TAR file")
        raise Exception("[extract_tar_archive] Not a valid TAR file")


@LOG
def extract_zip_archive(
    archive: str | Path = "",
    dest: str | Path = "",
    specific_files: list = [],
    LOGLEVEL: str = "INFO",
    logger=LOGGER,
):
    """Extrait tous les fichiers de l'archive ZIP contenant les modules et le VHDX.

    Args:
        archive (str): optionnel chemin complet du fichier zip
        dest (str): optionnel chemin complet de décompression de l'archive
        specific_files (tab): optionnel tableau avec le nom de fichier spécifiques à extraire
    """
    ret = None
    if not archive or not dest:
        logger.error("[extract_zip_archive] Args missing")
        raise Exception("[extract_zip_archive] Args missing")
    if zipfile.is_zipfile(archive):
        f_path = archive
        _archive = zipfile.ZipFile(archive)
        ret = _archive
        names = _archive.namelist()
        if names and specific_files:
            for name in names:
                # z1i = archive.getinfo(name)
                # for att in ('filename', 'file_size', 'compress_size', 'compress_type', 'date_time',  'CRC', 'comment'):
                #    LOGGER.error ('%s:\t' % att, getattr(z1i,att))
                if len(specific_files) > 0:
                    for i in range(len(specific_files)):
                        if specific_files[i] in name:
                            specific_files[i] = name
        try:
            if len(specific_files) > 0:
                for f in specific_files:
                    _archive.extract(f, path=dest)
            else:
                _archive.extractall(path=dest)
            _archive.close()
        except Exception as ex:
            _archive.close()
            logger.error(f"[extract_zip_archive] {str(ex)}")
            logger.info(f"[extract_zip_archive] Exec unzip command...")
            p = subprocess.Popen(
                ["unzip", "-x", "-d", dest, f_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                env=os.environ,
            )
            (output, err) = p.communicate()
            p_status = p.wait()
            logger.info(
                f"[extract_zip_archive] unzip status: {p_status} / error: {err}"
            )
            # raise ex
        return ret
    else:
        logger.error("[extract_zip_archive] Not a valid ZIP file")
        raise Exception("[extract_zip_archive] Not a valid ZIP file")


@LOG
def extract_gzip_archive(
    archive: str = "", dest: str = "", LOGLEVEL: str = "INFO", logger=LOGGER
):
    with gzip.open(archive, "rb") as f_in:
        with open(dest, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)


@LOG
def extract_7z_archive(
    archive: str | Path,
    dest: str | Path,
    password: str = "",
    LOGLEVEL: str = "INFO",
    logger=LOGGER,
) -> bool:
    try:
        if not archive or not dest:
            raise Exception("Args missing")
        with py7zr.SevenZipFile(archive, mode="r", password=password) as _archive:
            _archive.extractall(path=dest)
        return True
    except Exception as ex:
        logger.error(f"[extract_7z_archive] {ex}")
        return False


@LOG
def decrypt_orc_archive(
    archive: str | Path,
    dest: str | Path,
    private_key: str | Path,
    key_password: str = "",
    LOGLEVEL: str = "INFO",
    logger=LOGGER,
) -> tuple[bool, Path]:
    """
    Fonction qui déchiffre une archive DFIR-ORC chiffrée
    Args:
        archive (str): chemin de l'archive
        dest (str): chemin où extraire l'archive déchiffrée
        private_key (str): chemin de la clé privée pour déchiffrement
        key_password(str optionnal): password de la clé privée

    Returns:
        bool,str: success/failed, chemin complet de l'archive déchiffrée
    """
    try:
        _unstream = Path("src/bin/unstream")
        _input = Path(archive)
        _output = (Path(dest) / _input.stem).resolve()
        _cert = Path(private_key)
        res = decrypt_archive(
            archive_path=_input,
            private_key=_cert,
            output_file=_output,
            unstream_cmd=_unstream,
            log=logger,
        )
        if res:
            logger.info(f"[decrypt_orc_archive] Success")
        else:
            logger.error(f"[decrypt_orc_archive] ERROR")
        return res, _output
    except Exception as ex:
        logger.error(f"[decrypt_orc_archive] {ex}")
        return False, ""


@LOG
def detectEncoding(src: str = "", LOGLEVEL: str = "INFO", logger=LOGGER):
    if not src:
        return None
    result = chardet.detect(open(src, "rb").read())
    return result["encoding"]


@LOG
def rename_key_in_dict(
    mydict: dict = {},
    key: str = "",
    new_key: str = "",
    LOGLEVEL="INFO",
    logger=LOGGER,
) -> Optional[dict]:
    if not mydict:
        logger.error("[rename_key_in_dict] mydict is NONE [NOK]")
        return None
    elif type(mydict) is not dict:
        logger.error("[rename_key_in_dict] mydict is not a dict object [NOK]")
        return mydict
    mydict[new_key] = mydict.pop(key)
    logger.info(f"[rename_key_in_dict] Key changed {key} -> {new_key} [OK]")
    return mydict


@LOG
def import_timesketch(
    timelinename=None,
    file: str = "",
    timesketch_id: int = 0,
    LOGLEVEL: str = "INFO",
    logger=LOGGER,
):
    """Importe une timeline dans TimeSketch

    Args:
        timeline (str): Nom de la timeline
        file (str): fichier contenant la timeline
        timesketch_id (int): ID du sketch lié au client

    Returns:

    """
    # config file on triage /home/triage/.timesketchrc
    if not INTERNAL_CONFIG["administration"]["Timesketch"]["active"]:
        raise Exception("Timesketch module not active")
    if not timesketch_id:
        logger.error("[import_timesketch] sketch ID is NONE")
        raise Exception("[import_timesketch] sketch ID is NONE")
    if not file:
        logger.error("[import_timesketch] file is NONE")
        raise Exception("[import_timesketch] file is NONE")
    try:
        # ts = config.get_client(config_section="timesketch")
        _ts = client.TimesketchApi(
            host_uri=INTERNAL_CONFIG["administration"]["Timesketch"]["url"],
            username=INTERNAL_CONFIG["administration"]["Timesketch"]["username"],
            password=INTERNAL_CONFIG["administration"]["Timesketch"]["password"],
            verify=False,
            auth_mode="userpass",
        )
        if _ts:
            my_sketch = _ts.get_sketch(timesketch_id)
            with importer.ImportStreamer() as streamer:
                streamer.set_sketch(my_sketch)
                streamer.set_timeline_name(timelinename)
                streamer.add_file(file)
        else:
            raise Exception("TS instance is None, connection KO")
    except Exception as ex:
        # error "format code..." is in importer.py
        logger.error(f"[import_timesketch] {str(ex)}")


@LOG
def create_sketch(
    name: str = "",
    description: str = "",
    groups: list = ["IR"],
    public: bool = False,
    LOGLEVEL: str = "INFO",
    logger=LOGGER,
) -> int:
    """Création d'un nouveau sketch dans Timesketch

    Args:
        name (str): Nom du sketch
        description (str optionnal): description du sketch
        groups (list): liste des groupes ayant accès au sketch
        public (bool): Rendre le sketch public

    Returns:
        ID du sketch nouvellement créé
    """
    try:
        if not INTERNAL_CONFIG["administration"]["Timesketch"]["active"]:
            raise Exception("Timesketch module not active")
        _ts = client.TimesketchApi(
            host_uri=INTERNAL_CONFIG["administration"]["Timesketch"]["url"],
            username=INTERNAL_CONFIG["administration"]["Timesketch"]["username"],
            password=INTERNAL_CONFIG["administration"]["Timesketch"]["password"],
            verify=False,
            auth_mode="userpass",
        )
        if _ts:
            _sketch = _ts.create_sketch(name=name, description=description)
            _sketch.add_to_acl(group_list=groups, make_public=public)
            return _sketch.id
        else:
            raise Exception("TS instance is None, connection KO")
    except Exception as ex:
        logger.error(f"[create_sketch] {str(ex)}")
        # raise ex
        return 0


@LOG
def get_sketch_by_name(
    name: str = "",
    LOGLEVEL: str = "INFO",
    logger=LOGGER,
):
    """Retourne un sketch si le nom existe dans Timesketch

    Args:
        name (str): Nom du sketch

    Returns:
        Sketch or None
    """
    try:
        if not INTERNAL_CONFIG["administration"]["Timesketch"]["active"]:
            raise Exception("Timesketch module not active")
        _ts = client.TimesketchApi(
            host_uri=INTERNAL_CONFIG["administration"]["Timesketch"]["url"],
            username=INTERNAL_CONFIG["administration"]["Timesketch"]["username"],
            password=INTERNAL_CONFIG["administration"]["Timesketch"]["password"],
            verify=False,
            auth_mode="userpass",
        )
        if _ts:
            _found = None
            for _s in _ts.list_sketches():
                if _s.name.lower() == name.lower():
                    _found = _s
                    break
            return _found
        else:
            raise Exception("TS instance is None, connection KO")
    except Exception as ex:
        logger.error(f"[get_sketch_by_name] {str(ex)}")
        # raise ex
        return None


@LOG
def send_data_to_elk(
    data=None,
    ip: str = "",
    port: int = 0,
    extrafields: dict = {},
    LOGLEVEL: str = "INFO",
    logger=LOGGER,
):
    """Fonction qui envoie de la data vers ELK

     Args:
        data (obj): obj à envoyer (list de dict ou dict)
        ip (str): Adresse IP de ELK
        port (int): Port ELK qui reçoit les données
        client (str): Nom du client
        extrafields (dict): paramètres supplémentaires à ajouter au dict pour envoi

    Returns:
        number of event sent (int)
    """
    try:
        count = 0
        if not INTERNAL_CONFIG["administration"]["Logstash"]["active"]:
            raise Exception("Module Logstash not active")
        if not data or not ip or port == 0:
            logger.error("[send_data_to_elk] one or more args are not set")
            return None
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logger.info("[send_data_to_elk] socket created")
    except socket.error as err:
        logger.error(f"socket error: {err}")
        sock.close()
        raise err
    except Exception as e:
        logger.error(str(e))
        raise e
    try:
        logger.info(f"[send_data_to_elk] Try to connect to : {ip}:{port}")
        sock.connect((ip, port))
        logger.info(f"[send_data_to_elk] socket connected to : {ip}:{port}")
        logger.debug(f"[send_data_to_elk] Data type : {type(data)}")
        if type(data) is list:
            total = len(data)
            logger.info(f"[send_data_to_elk] Number of Data to send : {total}")
            logger.info("[send_data_to_elk] Sending...")
            _error_counter = 0
            for obj in data:
                try:
                    if type(obj) is dict:
                        obj.update(extrafields)
                        msg = f"{json.dumps(obj)}\n"
                        time.sleep(1 / 5000)
                        try:
                            sock.sendall(msg.encode())
                            count += 1
                        except socket.error as err:
                            if err.errno == 9:
                                sock.close()
                                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                sock.connect((ip, port))
                                sock.sendall(msg.encode())
                                logger.error(
                                    f"[send_data_to_elk] socket probably closed try reconnect"
                                )
                            else:
                                logger.error(f"[send_data_to_elk] socket: {err}")
                        except Exception as ex:
                            logger.error(f"[send_data_to_elk] {ex}")
                        if not count % 1000:
                            logger.debug(
                                f"[send_data_to_elk] Send part {count}/{total}"
                            )
                    else:
                        logger.warning(
                            "[send_data_to_elk] Not a dict obj... Not supported yet !"
                        )
                except Exception as ee:
                    _error_counter += 1
                    logger.error(f"[send_data_to_elk] {ee}")
            if count == total:
                logger.info("[send_data_to_elk] Data fully sent")
            else:
                logger.warning(f"[send_data_to_elk] {_error_counter} Packets not sent")
        if type(data) is dict:
            data.update(extrafields)
            msg = f"{json.dumps(data)}\n"
            time.sleep(1 / 5000)
            try:
                sock.sendall(msg.encode())
                count += 1
            except socket.error as err:
                if err.errno == 9:
                    sock.close()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((ip, port))
                    sock.sendall(msg.encode())
                    logger.error(
                        f"[send_data_to_elk] socket probably closed try reconnect"
                    )
                else:
                    logger.error(f"[send_data_to_elk] socket: {err}")
            except Exception as ex:
                logger.error(f"[send_data_to_elk] {ex}")
            logger.info("[send_data_to_elk] Data fully sent")
        sock.close()
    except Exception as e:
        if sock:
            sock.close()
        logger.error(f"[send_data_to_elk] {str(e)}")
        raise e
    finally:
        return count


@LOG
def send_jsonl_to_elk(
    filepath: str | Path,
    ip: str = "",
    port: int = 0,
    extrafields: dict = {},
    LOGLEVEL: str = "INFO",
    logger=LOGGER,
):
    """Fonction qui envoie tout le contenu d'un fichier JSONL vers ELK

     Args:
        filepath (str): chemin du fichier jsonl à envoyer
        ip (str): Adresse IP de ELK
        port (int): Port ELK qui reçoit les données
        client (str): Nom du client
        extrafields (dict): paramètres supplémentaires à ajouter au dict pour envoi

    Returns:
    """
    try:
        if not INTERNAL_CONFIG["administration"]["Logstash"]["active"]:
            raise Exception("Module Logstash not active")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        logger.info("[send_jsonl_to_elk] socket created")
        logger.info(f"[send_jsonl_to_elk] Try to connect to : {ip}:{port}")
        sock.connect((ip, port))
        logger.info(f"[send_jsonl_to_elk] socket connected to : {ip}:{port}")
        with open(filepath, "r") as jsonl_f:
            _line_number = 1
            for line in jsonl_f:
                try:
                    data = json.loads(line)
                    data.update(extrafields)
                    msg = f"{json.dumps(data)}\n"
                    time.sleep(1 / 5000)
                    try:
                        sock.sendall(msg.encode())
                    except socket.error as err:
                        if err.errno == 9:
                            logger.error(
                                f"[send_jsonl_to_elk] socket probably closed try reconnect"
                            )
                            sock.close()
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.connect((ip, port))
                            sock.sendall(msg.encode())
                        else:
                            logger.error(f"[send_jsonl_to_elk] socket: {err}")
                    except Exception as ex:
                        logger.error(f"[send_jsonl_to_elk] {ex}")
                except Exception as ee:
                    logger.error(f"[send_jsonl_to_elk 1] {ee} | line #{_line_number}")
                finally:
                    _line_number += 1
                    # sock.close()
            logger.info("[send_jsonl_to_elk] Data fully sent")
            sock.close()
    except Exception as e:
        logger.error(f"[send_jsonl_to_elk] {str(e)}")
        try:
            if sock:
                sock.close()
        except Exception as ex_sock:
            logger.error(f"[send_jsonl_to_elk] {str(ex_sock)}")
        raise e


@LOG
def zip_folder(
    zip_path: str = "",
    zip_name: str = "",
    target_dir: str = "",
    del_directory: bool = True,
    LOGLEVEL: str = "INFO",
    logger=LOGGER,
):
    try:
        if not zip_path or not zip_name or not target_dir:
            raise Exception("Missing param")
        if zip_path == target_dir:
            raise Exception("Zip cannot be in target dir")
        zipobj = zipfile.ZipFile(
            f"{zip_path}/{zip_name}.zip", "w", zipfile.ZIP_DEFLATED
        )
        rootlen = len(target_dir) + 1
        for base, dirs, files in os.walk(target_dir):
            for file in files:
                fn = os.path.join(base, file)
                zipobj.write(fn, fn[rootlen:])

        # files_to_save = [f"{zip_name}.zip"]
        # delete_files_in_directory(src=target_dir, files_to_save=files_to_save)
        if del_directory:
            if delete_directory(src=target_dir, logger=logger):
                logger.info("Directory deleted [OK]")
            else:
                logger.error("Directory deleted [NOK]")
    except Exception as ex:
        logger.error(f"[zip_folder] {str(ex)}")


@LOG
def csv_to_json(
    csvFilePath: str = "",
    jsonFilePath: str = "",
    delimiter: str = ";",
    encoding: str = "utf-8-sig",
    writeToFile: bool = False,
    writeasjsonline: bool = False,
    extrafields: dict = {},
    LOGLEVEL: str = "INFO",
    logger=LOGGER,
) -> list:
    """Fonction qui converti un csv en json

     Args:
        csvFilePath (str):nom du fichier csv
        jsonFilePath (str): nom du json pour export des resultats
        delimiter (str): delimiter du csv
        encoding (str): encodage du csv
        writeToFile (bool): write json to file

    Returns:
    """
    jsonArray = []

    # read csv file
    try:
        with open(csvFilePath, encoding=encoding) as csvf:
            dialect = csv.Sniffer().sniff(csvf.read(1024))
            csvf.seek(0)
            csvReader = csv.DictReader(csvf, dialect=dialect)
            for row in csvReader:
                row.update(extrafields)
                jsonArray.append(row)
    except UnicodeDecodeError as ex:
        logger.info(f"[csv_to_json] Encoding error try another...")
        with open(csvFilePath, encoding="latin-1") as csvf:
            dialect = csv.Sniffer().sniff(csvf.read(1024))
            csvf.seek(0)
            csvReader = csv.DictReader(csvf, dialect=dialect)
            for row in csvReader:
                row.update(extrafields)
                jsonArray.append(row)
        logger.info(f"[csv_to_json] Done")
    if writeToFile:
        with open(jsonFilePath, "w", encoding="utf-8") as jsonf:
            if writeasjsonline:
                for _entry in jsonArray:
                    json.dump(_entry, jsonf)
                    jsonf.write("\n")
            else:
                jsonString = json.dumps(jsonArray, indent=4)
                jsonf.write(jsonString)
    return jsonArray


@LOG
def txt_to_json(
    FilePath: str = "",
    jsonFilePath: str = "",
    sanitize: bool = False,
    encoding: str = "",
    writeToFile: bool = False,
    extrafields: dict = {},
    LOGLEVEL: str = "INFO",
    step: int = 16,
    logger=LOGGER,
) -> dict:
    """Fonction qui lit un fichier texte en json

     Args:
        FilePath (str):nom du fichier
        jsonFilePath (str): nom du json pour export des resultats
        encoding (str): encodage du fichier
        writeToFile (bool): write json to file
        step (int) : chunk size

    Returns:
    """
    jsons = extrafields
    jsons["data"] = dict()
    if not encoding:
        try:
            with open(FilePath, "rb") as inr:
                result = detect(inr.read(step))
                if result["encoding"] is not None:
                    encoding = result["encoding"]
        except IOError as ex:
            logger.error(f"[txt_to_json] Could not determine encoding {str(ex)}")
    try:
        with open(FilePath, mode="r", encoding=encoding) as infile:
            # load txt file data using readline
            _count = 0
            _rot = 0
            _tab = []
            for _line in infile.readlines():
                if _line not in [[], "", None, " ", "\n", "\t"]:
                    _tab.append(_line.rstrip("\n"))
                if _count < step:
                    _count += 1
                else:
                    jsons["data"][f"chunk_{_rot}"] = _tab
                    _rot += 1
                    _count = 0
                    _tab = []
    except Exception as er:
        logger.error(f"[txt_to_json] Could not translate to json {str(er)}")
    if writeToFile:
        with open(jsonFilePath, "w", encoding="utf-8") as jsonf:
            jsonString = json.dumps(jsons, indent=4)
            jsonf.write(jsonString)
    return jsons


@LOG
def extract_file_name(path=None, extension=None) -> dict:
    """Fonction qui extrait le nom de fichier sur la base de son extension
    Args:
        path (str): chemin complet du fichier à extraire
        extension (str): extension du fichier attendu, SANS POINT !
    Returns :
        dict containing 'directory', 'name', 'fullpath' and 'module' strings
    """
    # pattern = f"^(.+\/)(.+\.{extension})$" => for ADAudit
    pattern = f"^((.+\/)?(.*)?\/)(.+\.{extension})$"
    objpath = {"directory": None, "name": None}
    if match := re.search(pattern, path, re.IGNORECASE):
        objpath["fullpath"] = match.group(0)
        objpath["directory"] = match.group(2)
        objpath["module"] = match.group(3)
        objpath["name"] = match.group(4)
    return objpath


@LOG
def _test_file_magic(filepath: str = "", magic=[], logger=LOGGER) -> bool:
    try:
        with open(filepath, "rb") as test_f:
            for signature in magic:
                lbr = len(signature)
                if test_f.read(lbr) == signature:
                    return True
        return False
    except IOError as e:
        logger.error(f"[test_file_magic] Could not read input buffer {str(e)}")
        return False


@LOG
def eval_file_format(path: str = "", logger=LOGGER) -> dict:
    """
    Identification de format d'archive
    returns:
    - dict containing 'format' and 'lib' to use
    """
    res = {"format": ""}
    for m in magics.keys():
        if _test_file_magic(magic=magics[m], filepath=path):
            return {"format": m}
        elif path.endswith(".7z.p7b"):
            return {"format": ".7z.p7b"}
        else:
            return res
    return res


@LOG
def update_dict(x, y, logger=LOGGER) -> dict:
    """
    Fonction pour update un dict de tableaux
    Args :
    - x : dict de tableau de référence
    - y : dict de tableaux à ajouter
    """
    for i in x.keys():
        try:
            x[i].extend(y[i])
            del y[i]
        except KeyError:
            logger.error(f"[update_dict] Key {i} does not exists in x or y")
            continue
        except Exception as e:
            logger.error(f"[update_dict] Error mergin' dicts at key {i} : {e}")
            continue
    x.update(y)
    return x


@LOG
def generate_filebeat_config(
    ip: str,
    port: int,
    client: str,
    hostname: str,
    LOGLEVEL: str = "INFO",
    logger=LOGGER,
) -> dict:
    try:
        _config = dict()
        _config["filebeat.config"] = dict()
        _config["filebeat.config"]["modules"] = dict()
        _config["filebeat.config"]["modules"]["path"] = "${path.config}/modules.d/*.yml"
        _config["filebeat.config"]["modules"]["reload.enabled"] = False

        _config["filebeat.modules"] = list()
        _module = dict()
        _module["module"] = "apache"
        _module["access"] = dict()
        _module["access"]["enabled"] = True
        _module["access"]["input"] = dict()
        _module["access"]["input"]["close_eof"] = True
        _module["access"]["var.paths"] = ["/tmp/apache/**/*access.log*"]
        _module["error"] = dict()
        _module["error"]["enabled"] = True
        _module["error"]["input"] = dict()
        _module["error"]["input"]["close_eof"] = True
        _module["error"]["var.paths"] = ["/tmp/apache/**/*error.log*"]
        _config["filebeat.modules"].append(_module)

        _module = dict()
        _module["module"] = "auditd"
        _module["log"] = dict()
        _module["log"]["enabled"] = True
        _module["log"]["input"] = dict()
        _module["log"]["input"]["close_eof"] = True
        _module["log"]["var.paths"] = ["/tmp/auditd/**/*audit.log*"]
        _config["filebeat.modules"].append(_module)

        _module = dict()
        _module["module"] = "nginx"
        _module["access"] = dict()
        _module["access"]["enabled"] = True
        _module["access"]["input"] = dict()
        _module["access"]["input"]["close_eof"] = True
        _module["access"]["var.paths"] = ["/tmp/nginx/**/*access.log*"]
        _module["error"] = dict()
        _module["error"]["enabled"] = True
        _module["error"]["input"] = dict()
        _module["error"]["input"]["close_eof"] = True
        _module["error"]["var.paths"] = ["/tmp/nginx/**/*error.log*"]
        _config["filebeat.modules"].append(_module)

        _module = dict()
        _module["module"] = "suricata"
        _module["eve"] = dict()
        _module["eve"]["enabled"] = True
        _module["eve"]["input"] = dict()
        _module["eve"]["input"]["close_eof"] = True
        _module["eve"]["var.paths"] = ["/tmp/suricata/*eve.json*"]
        _config["filebeat.modules"].append(_module)

        _module = dict()
        _module["module"] = "system"
        _module["auth"] = dict()
        _module["auth"]["enabled"] = True
        _module["auth"]["input"] = dict()
        _module["auth"]["input"]["close_eof"] = True
        _module["auth"]["var.paths"] = ["/tmp/system/**/*auth.log*"]
        _module["syslog"] = dict()
        _module["syslog"]["enabled"] = True
        _module["syslog"]["input"] = dict()
        _module["syslog"]["input"]["close_eof"] = True
        _module["syslog"]["var.paths"] = ["/tmp/system/**/*syslog*"]
        _config["filebeat.modules"].append(_module)

        _module = dict()
        _module["module"] = "tomcat"
        _module["log"] = dict()
        _module["log"]["enabled"] = True
        _module["log"]["input"] = dict()
        _module["log"]["input"]["close_eof"] = True
        _module["log"]["input"]["multiline.match"] = "after"
        _module["log"]["input"]["multiline.negate"] = False
        _module["log"]["input"][
            "multiline.pattern"
        ] = "^[[:space:]]+(at|\.{3})[[:space:]]+\b|^Caused by:"
        _module["log"]["input"]["multiline.type"] = "pattern"
        _module["log"]["var.input"] = "file"
        _module["log"]["var.paths"] = ["/tmp/tomcat/**/*catalina.out*"]
        _config["filebeat.modules"].append(_module)

        _config["output.logstash"] = dict()
        _config["output.logstash"]["enabled"] = True
        _config["output.logstash"]["hosts"] = [f"{ip}:{port}"]
        _config["processors"] = list()
        _config["processors"].append(
            {
                "add_fields": {
                    "target": "csirt",
                    "fields": {
                        "application": "filebeat",
                        "client": client,
                        "hostname": hostname,
                    },
                }
            }
        )
        return _config
    except Exception as ex:
        logger.error(f"[generate_filebeat_config] {str(ex)}")
        return {}


@LOG
def generate_fortinet_filebeat_config(
    ip: str,
    port: int,
    client: str,
    hostname: str,
    LOGLEVEL: str = "INFO",
    logger=LOGGER,
) -> dict:
    try:
        _config = dict()
        _config["filebeat.config"] = dict()
        _config["filebeat.config"]["modules"] = dict()
        _config["filebeat.config"]["modules"]["path"] = "${path.config}/modules.d/*.yml"
        _config["filebeat.config"]["modules"]["reload.enabled"] = False
        _config["filebeat.modules"] = list()
        _module = dict()
        _module["module"] = "fortinet"
        _module["firewall"] = dict()
        _module["firewall"]["enabled"] = True
        _module["firewall"]["var.input"] = "file"
        _module["firewall"]["input"] = dict()
        _module["firewall"]["input"]["close_eof"] = True
        _module["firewall"]["var.paths"] = ["/fortinet/**/*.log*"]
        _config["filebeat.modules"].append(_module)

        _config["output.logstash"] = dict()
        _config["output.logstash"]["enabled"] = True
        _config["output.logstash"]["hosts"] = [f"{ip}:{port}"]
        _config["processors"] = list()
        _config["processors"].append(
            {
                "add_fields": {
                    "target": "csirt",
                    "fields": {
                        "application": "fortinet",
                        "client": client,
                        "hostname": hostname,
                    },
                }
            }
        )
        return _config
    except Exception as ex:
        logger.error(f"[generate_fortinet_filebeat_config] {str(ex)}")
        return {}


@LOG
def update_config_file(
    data: dict, conf_file: str, LOGLEVEL: str = "NOLOG", logger=LOGGER
) -> bool:
    try:
        with open(conf_file, "w") as config_file:
            yaml.dump(data, config_file, sort_keys=False)
        return True
    except Exception as ex:
        logger.error(f"[update_config_file] {str(ex)}")
        return False


@LOG
def convert_json_to_jsonl(
    input_file: Path, output_file: Path, LOGLEVEL: str = "INFO", logger=LOGGER
) -> bool:
    try:
        data_dict = None
        with open(input_file, "r") as _input_json:
            data_dict = json.load(_input_json)
        with open(output_file, "w") as _jsonl_output:
            try:
                if isinstance(data_dict, list):
                    for _entry in data_dict:
                        json.dump(_entry, _jsonl_output)
                        _jsonl_output.write("\n")
                elif isinstance(data_dict, dict):
                    json.dump(data_dict, _jsonl_output)
                    _jsonl_output.write("\n")
                else:
                    logger.error(f"[convert_json_to_jsonl] Not a dict or list")
                    return False
            except Exception as ex:
                logger.error(f"[convert_json_to_jsonl] {str(ex)}")
        return True
    except Exception as ex:
        logger.error(f"[convert_json_to_jsonl] {str(ex)}")
        return False


@LOG
def get_file_informations(
    filepath: Path, LOGLEVEL: str = "INFO", logger=LOGGER
) -> dict:
    try:
        _res = dict()
        _infos = os.stat(filepath)
        _res["lastWriteTime"] = datetime.fromtimestamp(_infos.st_mtime).isoformat()
        _res["creationTime"] = datetime.fromtimestamp(_infos.st_ctime).isoformat()
        _res["lastAccessTime"] = datetime.fromtimestamp(_infos.st_atime).isoformat()
        _res["fileSize"] = _infos.st_size
        _res["filepath"] = str(filepath)
        _res["numberOfLogRecords"] = 0
        _res["numberOfEventSent"] = 0
        _res["attributes"] = 0
        return _res
    except Exception as ex:
        if logger:
            logger.error(f"[get_file_informations] {ex}")
        return {}


@LOG
def generate_analytics(LOGLEVEL: str = "INFO", logger=LOGGER) -> dict:
    try:
        _analytics = dict()
        _analytics["log"] = dict()
        _analytics["log"]["file"] = dict()
        _analytics["log"]["file"]["eventcount"] = 0
        _analytics["log"]["file"]["eventsent"] = 0
        _analytics["log"]["file"]["attributes"] = 0
        _analytics["log"]["file"]["path"] = ""
        _analytics["log"]["file"]["size"] = 0
        _analytics["log"]["file"]["lastaccessed"] = ""
        _analytics["log"]["file"]["creation"] = ""

        _analytics["csirt"] = dict()
        _analytics["csirt"]["client"] = ""
        _analytics["csirt"]["hostname"] = ""
        _analytics["csirt"]["application"] = ""
        return _analytics
    except Exception as ex:
        logger.error(f"[generate_analytics] {ex}")
        return dict()
