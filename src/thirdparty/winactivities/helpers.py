import string
import _string
import sqlite3
import datetime


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def datetime_decode_1970_str(datetime_int):
    if datetime_int == 0:
        return 0

    if datetime_int:
        return datetime_decode_1970(datetime_int).isoformat(" ")

    return None


def datetime_decode_1970(datetime_int):
    time_delta = datetime.timedelta(seconds=datetime_int)

    orig_datetime = datetime.datetime(1970, 1, 1)
    new_datetime = orig_datetime + time_delta

    return new_datetime


class CustomStringFormatter(string.Formatter):
    def __init__(self, default_value=""):
        self._default_value = default_value

    def _vformat(
        self, format_string, args, kwargs, used_args, recursion_depth, auto_arg_index=0
    ):
        if recursion_depth < 0:
            raise ValueError("Max string recursion exceeded")
        result = []
        for literal_text, field_name, format_spec, conversion in self.parse(
            format_string
        ):
            # output the literal text
            if literal_text:
                result.append(literal_text)

            # if there's a field, output it
            if field_name is not None:
                # this is some markup, find the object and do
                #  the formatting

                # given the field_name, find the object it references
                #  and the argument it came from
                try:
                    obj, arg_used = self.get_field(field_name, args, kwargs)
                    used_args.add(arg_used)
                except Exception as error:
                    obj = ""

                # do any conversion on the resulting object
                obj = self.convert_field(obj, conversion)

                # expand the format spec, if needed
                format_spec, auto_arg_index = self._vformat(
                    format_spec,
                    args,
                    kwargs,
                    used_args,
                    recursion_depth - 1,
                    auto_arg_index=auto_arg_index,
                )

                # format the object and append to the result
                result.append(self.format_field(obj, format_spec))

        return "".join(result), auto_arg_index

    def get_field(self, field_name, args, kwargs):
        first, rest = _string.formatter_field_name_split(field_name)

        obj = self.get_value(first, args, kwargs)

        for is_attr, i in rest:
            if is_attr:
                obj = getattr(obj, i)
            else:
                obj = obj[i]

        return obj, first

    def get_value(self, key, args, kwargs):
        if isinstance(key, str) or isinstance(key, bytes):
            value = kwargs.get(key, self._default_value)
            return value
        else:
            value = string.Formatter.get_value(key, args, kwargs)
            return value


class DbHandler(object):
    def __init__(self, **kwargs):
        self.properties = kwargs

    def get_connection(self):
        return sqlite3.connect(**self.properties)

    def iter_rows(self, query):
        try:
            connection = self.get_connection()
            connection.row_factory = dict_factory
            cursor = connection.cursor()
            cursor.execute(query)

            for row in cursor:
                yield row
            cursor.close()
        except Exception as ex:
            print(f"[Error iter_rows] {ex}")
            if cursor:
                cursor.close()
