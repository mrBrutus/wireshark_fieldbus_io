"""Helpers for the `wireshark_fieldbus_io` package"""
from dataclasses import dataclass, fields
from functools import wraps
from time import time


def timing(f):
    """Decorator for function timing in `ms`"""

    @wraps(f)
    def wrap(*args, **kw):
        ts = time()
        result = f(*args, **kw)
        te = time()
        print(f'processing "{f.__name__}" took {(te-ts)*1000:2.3f} ms')
        return result
    return wrap


@dataclass
class MyDataClass:
    """`DataClass` with some additional properties+methods added:
    - `items()`
    - `keys`
    - `values`
    """

    def items(self):
        """Returns iterator with key, value tuples of the dataclass"""

        for item in fields(self):
            yield item.name, getattr(self, item.name)

    @property
    def keys(self):
        """List of keys in the dataclass"""

        return [field.name for field in fields(self)]

    @property
    def values(self):
        """List of values in the dataclass"""

        return [getattr(self, field.name) for field in fields(self)]
