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

    This module provides functionality to retrieve application secrets either from
    local environment variables or from Azure Key Vault. The mode of retrieval is
    determined by the application's environment setting.

    @author: S. Nair
    @contact: sachin.nair@in.ey.com
"""
import os
from typing import Union
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
from core.config import settings
from utils.custom_logging import log

keys = [
    # 'AD-AUTHORITY',
    # 'AD-CLIENT-ID',
    # 'AD-CLIENT-SECRET',
    # 'AD-REDIRECT-URI',
    'DB-SERVER-NAME',
    'DB-PORT',
    'DB-NAME',
    'DB-USERNAME',
    'DB-PASSWORD',
    'REDIS-HOST',
    'REDIS-PORT',
    'REDIS-PASSWORD',
    'TOKEN-SECRET-KEY',
]

KEYS_DICTIONARY = {}


def get_key(key: str) -> Union[str | None]:
    """
        Retrieves the value of a specified key from local environment variables or Azure Key Vault.
    """
    if settings.environment == 'local':
        # Get key from local environment variable
        key = settings.project_name_short + "_" + key.replace("-", "_")

        if key in KEYS_DICTIONARY:
            return KEYS_DICTIONARY[key]

        key_value = os.getenv(key)
        if key_value is None:
            raise ValueError(f'{key} environment variable is not set.')
        KEYS_DICTIONARY[key] = key_value
        return key_value

    # Get key from Azure Key Vault
    key_vault_url = os.getenv(settings.project_name_short + '_KEY_VAULT_URL')
    if not key_vault_url:
        raise ValueError(settings.project_name_short + '_KEY_VAULT_URL environment variable is not set.')
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=key_vault_url, credential=credential)
    try:
        if key in KEYS_DICTIONARY:
            return KEYS_DICTIONARY[key]

        retrieved_secret = client.get_secret(key)
        KEYS_DICTIONARY[key] = retrieved_secret.value
        return retrieved_secret.value
    except Exception as exception:
        log.error('Failed to retrieve secret %s from Azure Key Vault: %s', key, exception)
        raise ValueError(key + ' Key Vault variable is not set.') from exception


def validate_all_keys() -> None:
    """
        Check if all keys are created
    """

    for key in keys:
        # Validating if all variables exist
        log.debug('Validating Key: %s', key)
        _ = get_key(key)

    log.info('All keys exist in Env Variables/ Key Vault')
