"""
    Copyright 2020-2024 AND Confidential Information of EY LLP. All rights reserved.
    Only authorised EY LLP employees and authorised contractors may utilise the software or codes
    (in source and binary forms, with or without modification) subject to the following conditions:
    * Only in performance of work for EY LLP;
    * NO licence is granted to any party not so authorised;
    * The above copyright notice and this permission notice shall be included in all copies or
    substantial portions of the software.
    
    THE SOFTWARE AND/OR THE CODES ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
    PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
    LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE USE OR OTHER DEALINGS
    OF THE SOFTWARE AND/OR THE CODES.
    
    Module to initialize Redis

    @author: S. Nair
    @contact: sachin.nair@in.ey.com
"""

import pickle
from typing import Any, Union

import redis
import redis.asyncio as async_redis
from core import key_vault_manager
from core.config import settings
from utils.custom_logging import log
from utils.helpers import dict_hash


class Redis:
    """
        Class to initialize redis connection and perform crud operation
    """

    def __init__(self) -> None:
        redis_host = key_vault_manager.get_key('REDIS-HOST')
        redis_port = key_vault_manager.get_key('REDIS-PORT')
        redis_password = key_vault_manager.get_key('REDIS-PASSWORD')

        self.redis_client = redis.Redis(host=redis_host, port=redis_port, password=redis_password, ssl=not redis_port == '6379', ssl_cert_reqs=None, max_connections=settings.redis_pool_size)
        self.redis_client.ping()
        #self.redis_client.flushall()
        log.info('Redis Connection Initialized')

    def retrieve_from_cache(self, key: str) -> Any:
        """
            Retrieve key from cache
        """
        cache_object_hash = dict_hash(key)
        if self.redis_client.exists(cache_object_hash):
            return pickle.loads(self.redis_client.get(cache_object_hash))
        return None

    def add_to_cache(self, key: str, value: Any, ttl: Union[int | None] = None) -> None:
        """
            Add key to cache
        """
        cache_object_hash = dict_hash(key)
        self.redis_client.set(cache_object_hash, pickle.dumps(value))
        if ttl:
            self.redis_client.expire(cache_object_hash, time=ttl)

    def delete_from_cache(self, key) -> None:
        """
            Delete key from cache
        """
        cache_object_hash = dict_hash(key)
        self.redis_client.delete(cache_object_hash)

    def retrieve_from_cache_hash(self, hash_name: str, key: str) -> Any:
        """
            Retrieve key from hash
        """
        cache_object_hash = dict_hash(key)
        if self.redis_client.hexists(hash_name, cache_object_hash):
            return pickle.loads(self.redis_client.hget(hash_name, cache_object_hash))
        return None

    def add_to_cache_hash(self, hash_name: str, key: str, value: Any, ttl: Union[int | None] = None) -> None:
        """
            Add key to hash
        """
        cache_object_hash = dict_hash(key)
        self.redis_client.hset(hash_name, cache_object_hash, pickle.dumps(value))
        if ttl:
            self.redis_client.expire(hash_name + ':' + cache_object_hash, time=ttl)

    def delete_from_cache_hash(self, hash_name: str, key: Union[str | None] = None) -> None:
        """
            Delete key from hash
        """
        if key is None:
            self.redis_client.delete(hash_name)
        else:
            cache_object_hash = dict_hash(key)
            self.redis_client.hdel(hash_name, cache_object_hash)


class AsyncRedis:
    """
            Class to initialize async redis connection
    """

    def __init__(self) -> None:
        redis_host = key_vault_manager.get_key('REDIS-HOST')
        redis_port = key_vault_manager.get_key('REDIS-PORT')
        redis_password = key_vault_manager.get_key('REDIS-PASSWORD')

        self.redis_client = async_redis.Redis(host=redis_host, port=redis_port, password=redis_password, ssl=not redis_port == '6379', ssl_cert_reqs=None, max_connections=settings.redis_pool_size)
        log.info('Async Redis Connection Initialized')


redis_client = Redis()
async_redis_client = AsyncRedis()
