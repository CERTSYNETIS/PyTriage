from __future__ import division
from datetime import datetime, timedelta, tzinfo
from calendar import timegm

EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
HUNDREDS_OF_NANOSECONDS = 10000000
HOUR = timedelta(hours=1)

UNITS = {1000: ["KB", "MB", "GB"], 1024: ["KiB", "MiB", "GiB"]}


class UTC(tzinfo):
    def utcoffset(self, dt):
        return timedelta(0)

    def tzname(self, dt):
        return "UTC"

    def dst(self, dt):
        return timedelta(0)


utc = UTC()


class UTCTime(object):
    @staticmethod
    def time_to_date(ft):
        try:
            return datetime.utcfromtimestamp(
                (ft - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS
            )
        except ValueError:
            return "year is out of range"

    @staticmethod
    def date_to_time(dt):
        if (dt.tzinfo is None) or (dt.tzinfo.utcoffset(dt) is None):
            dt = dt.replace(tzinfo=utc)

        return EPOCH_AS_FILETIME + (timegm(dt.timetuple()) * HUNDREDS_OF_NANOSECONDS)


def approximate_date(timestamp) -> str:
    return UTCTime.time_to_date(timestamp).strftime("%d/%m/%Y - %H:%M:%S")


def approximate_time(timestamp):
    dt = approximate_date(timestamp)
    td = dt - datetime(1970, 1, 1)

    return (td.microseconds + (td.seconds + td.days * 86400) * 10**6) / 10**6


def approximate_size(size, flag_1024_or_1000=True):
    mult = 1000
    for unit in UNITS[mult]:
        size = size / mult
        if size < mult:
            return "{0:.3f} {1}".format(size, unit)
