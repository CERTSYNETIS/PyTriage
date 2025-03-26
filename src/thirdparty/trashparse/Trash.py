from __future__ import unicode_literals
from ._helper import bytes_to_long
from unidecode import unidecode
import os


class Trash(object):
    def __init__(self, path):
        self.handle = open(path, "rb")
        self.data = self.handle.read()

    @property
    def name(self):
        return self.handle.name

    @property
    def dirname(self):
        return os.path.dirname(self.name)

    @property
    def basename(self):
        return os.path.basename(self.name)

    @property
    def content(self):
        path = os.path.join(self.dirname, "$R" + self.basename[2:])

        with open(path) as handle:
            return handle.read()


class TrashInfo(Trash):
    @property
    def index_type(self):
        return "$I"

    @property
    def version(self):
        if bytes_to_long(self.data[:4]) == 2:
            return "Win 10"

        return "Win Vista-8.1"

    @property
    def filesize(self):
        return bytes_to_long(self.data[8:16])

    @property
    def deleted_time(self):
        return bytes_to_long(self.data[16:24])

    @property
    def original_path_length(self):
        if self.version == "Win 10":
            return bytes_to_long(self.data[24:28])

    @property
    def original_path(self):
        if self.version == "Win 10":
            pathname = self.data[28:]
        else:
            pathname = self.data[24:]

        try:
            pathname = pathname[::2][:-1].decode()
        except UnicodeError:
            pathname = pathname[::2][:-1].decode("ISO-8859-1")

        return unidecode(pathname).strip("\x00")

    @property
    def original_name(self):
        return os.path.basename(self.original_path.replace("\\", "/"))

    @property
    def extension(self):
        return os.path.splitext(self.original_name)[-1]

    @property
    def type(self):
        if self.extension or self.filesize > 0:
            return "file"
        return "dir"


class TrashInfo2(Trash):
    pass


def identify_type(name):
    assert name.startswith("$I") or name.startswith(
        "INFO2"
    ), "cannot identify artifact file '%s'" % (name)

    return "$I" if name.startswith("$I") else "INFO2"


def inspect(path):
    basename = os.path.basename(path)
    identified_type = identify_type(basename)

    return TrashInfo(path)
