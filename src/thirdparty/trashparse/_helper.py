import struct


def bytes_to_long(byte, format="<Q"):
    if len(byte) == 4:
        format = "<I"

    return struct.unpack(format, byte)[0]


def long_to_bytes(number, format="<Q"):
    if len(bytes) == 4:
        format = "<I"

    return struct.pack(format, number)
