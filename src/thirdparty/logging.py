from logging import basicConfig, getLogger, Logger, FileHandler, Formatter, INFO
from .triageutils import INTERNAL_CONFIG

LOG_FOLDER = INTERNAL_CONFIG["general"]["logfolder"]  # /log"

basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%d-%m-%Y %H:%M:%S",
    level="DEBUG",
)


def get_logger(name: str) -> Logger:
    _new_name = f"pytriage_{name}"
    file_handler = FileHandler(filename=f"{LOG_FOLDER}/{name}.log", mode="a")
    formatter = Formatter("%(asctime)s - %(levelname)s - %(message)s")
    _logger = getLogger(_new_name)
    file_handler.setLevel(INFO)
    file_handler.setFormatter(formatter)
    _exists = False
    for h in _logger.handlers:
        if name in h.baseFilename:
            _exists = True
            break
            # l.removeHandler(h)
    if not _exists:
        _logger.addHandler(file_handler)
    return _logger


if __name__ == "__main__":
    print(LOG_FOLDER)
