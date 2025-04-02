"""
    Copyright 2020-2024 AND Confidential Information of EY LLP. All rights reserved.
    Only authorised EY LLP employees and authorised contractors may utilise the software or codes
    (in source and binary forms, with or without modification) subject to the following conditions:
    * Only in performance of work for EY LLP;
    * NO licence is granted to any party not so authorised;
    * The above copyright notice and this permission notice shall be included in all copies or
    substantial portions of the software.

    THE SOFTWARE AND/OR THE CODES ARE PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
    PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
    LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE USE OR OTHER DEALINGS
    OF THE SOFTWARE AND/OR THE CODES.

    Helpers used across the project

    @author: S. Nair
    @contact: sachin.nair@in.ey.com
"""

import threading
import uuid
from typing import Any, Union
import json
import hashlib
import redis
from utils.custom_logging import log


def generate_uuid():
    """
        Generate UUID V4 identifier
    """
    return str(uuid.uuid4())


def dict_hash(input_dict: dict) -> str:
    """
        Converts input dictionary to SHA-256 hash
    """
    dhash = hashlib.sha256()
    encoded = json.dumps(input_dict, sort_keys=True).encode()
    dhash.update(encoded)
    return dhash.hexdigest()


def dict_to_str(input_dict: dict) -> str:
    """
        Converts input dictionary to string
    """
    return json.dumps(input_dict)


def str_to_dict(input_str: str) -> dict:
    """
        Converts input dictionary to string
    """
    return json.loads(input_str)


def get_file_hash(file_path):
    """
        Returns file sha256 hash
    """
    hash_sha256 = hashlib.sha256()

    with open(file_path, "rb") as file_data:
        for chunk in iter(lambda: file_data.read(4096), b""):
            hash_sha256.update(chunk)

    file_hash = hash_sha256.hexdigest()

    return file_hash


class RedisDict:
    """
        Dictionary using Redis Client
    """

    def __init__(self, redis_connection: redis.client.Redis, redis_key_prefix: str, redis_key_ttl: Union[int | None] = None):
        self.redis = redis_connection
        self.key_prefix = redis_key_prefix
        self.redis_key_ttl = redis_key_ttl

    def _full_key(self, key: str):
        return f"{self.key_prefix}:{key}"

    def __setitem__(self, key: str, value: Any):
        self.redis.set(self._full_key(key), value)
        if self.redis_key_ttl:
            self.redis.expire(self._full_key(key), time=self.redis_key_ttl)

    def __getitem__(self, key: str):
        value = self.redis.get(self._full_key(key))
        if value is None:
            raise KeyError(f"Key '{key}' not found in Redis")
        return value.decode("utf-8")

    def __delitem__(self, key: str):
        if self._full_key(key) not in self.redis:
            raise KeyError(f"Key '{key}' not found in Redis")
        self.redis.delete(self._full_key(key))

    def __contains__(self, key: str):
        return self.redis.exists(self._full_key(key))

    def keys(self) -> list[Any]:
        """
            Return all keys inside dictionary
        """
        pattern = f"{self.key_prefix}:*"
        return [key.decode("utf-8").split(":", 1)[1] for key in self.redis.keys(pattern)]

    def __iter__(self):
        return iter(self.keys())

    def __len__(self):
        return len(self.keys())

    def clear(self) -> None:
        """
            Remove all keys from dictionary
        """
        for key in self.keys():
            self.redis.delete(self._full_key(key))

    def items(self) -> list[tuple[str, Any]]:
        """
            Returns all key-value pairs as tuples
        """
        return [(key, self[key]) for key in self.keys()]

    def values(self) -> list[Any]:
        """
            Returns all values in dictionary
        """
        return [self[key] for key in self.keys()]


class TimedDict:
    """
        Dictionary where the keys are removed once the timeout duration has expired
    """

    def __init__(self, timeout=600) -> None:
        self.data = {}
        self.timeout = timeout

    def set(self, key: str, value: Any) -> None:
        """Adds a key-value pair to the dictionary and sets a timer to remove it after `timeout` seconds."""
        self.data[key] = value
        # Start a timer that will delete the key after the specified timeout
        timer = threading.Timer(self.timeout, self._delete, args=[key])
        timer.start()

    def _delete(self, key: str) -> None:
        """Deletes the key from the dictionary."""
        if key in self.data:
            del self.data[key]
            log.debug("Key '%s' has been deleted.", key)

    def get(self, key: str) -> Any:
        """Gets the value for the specified key."""
        return self.data.get(key, None)

    def __repr__(self) -> str:
        return str(self.data)
