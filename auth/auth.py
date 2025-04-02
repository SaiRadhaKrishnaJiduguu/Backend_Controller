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

    Module related to authentication

    @author: S. Nair
    @contact: sachin.nair@in.ey.com
"""
import urllib
from datetime import datetime, timedelta
from typing import Union
import time
import json
import jwt
from passlib.context import CryptContext
from msal import ConfidentialClientApplication
from core import key_vault_manager
from core.config import settings
from core.redis_manager import redis_client
from utils.custom_logging import log
from utils.helpers import RedisDict

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class AzureAD:
    """
        Azure AD class
    """
    well_known = None


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
        Verify plain text password with hashed password
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
        Returns hashed password
    """
    return pwd_context.hash(password)


def create_access_token(data: dict) -> tuple[str, int]:
    """
        Generates Access Token using the provided payload
    """
    payload = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expiry)
    expiry_unix = int(time.time() + (settings.access_token_expiry * 60))
    payload.update({"exp": expire.timestamp()})
    encoded_jwt = jwt.encode(payload, key_vault_manager.get_key('TOKEN-SECRET-KEY'), algorithm=settings.jwt_algorithm)
    return encoded_jwt, expiry_unix


def create_refresh_token(data: dict) -> str:
    """
        Generates Refresh Token using the provided payload
    """
    payload = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=settings.refresh_token_expiry)
    payload.update({"exp": expire.timestamp()})
    encoded_jwt = jwt.encode(payload, key_vault_manager.get_key('TOKEN-SECRET-KEY'), algorithm=settings.jwt_algorithm)
    return encoded_jwt


def decode_token(token: str) -> Union[dict, None]:
    """
        Decode Access token
    """
    try:
        payload = jwt.decode(token, key_vault_manager.get_key('TOKEN-SECRET-KEY'), algorithms=[settings.jwt_algorithm])
        return payload
    except jwt.ExpiredSignatureError:
        log.error('Access token expired')
        return None
    except jwt.InvalidTokenError:
        return None


def decode_ad_access_token(jwt_token: str):
    """
        Decode AD access token.
    """

    if AzureAD.well_known is None:
        well_known_url = key_vault_manager.get_key("AD-AUTHORITY") + '/v2.0/.well-known/openid-configuration'
        with urllib.request.urlopen(well_known_url) as response:
            well_known = json.load(response)
            AzureAD.well_known = well_known

    if 'jwks_uri' not in AzureAD.well_known:
        raise ValueError('jwks_uri not found in OpenID configuration')
    jwks_url = AzureAD.well_known['jwks_uri']
    jwks_client = jwt.PyJWKClient(jwks_url)
    header = jwt.get_unverified_header(jwt_token)
    key = jwks_client.get_signing_key(header['kid']).key
    return jwt.decode(jwt_token, key, [header['alg']],
                      audience=key_vault_manager.get_key("AD-CLIENT-ID"), options={'verify_signature': True})


def decode_refresh_token(token: str) -> Union[dict, None]:
    """
        Decode Refresh token
    """
    try:
        payload = jwt.decode(token, key_vault_manager.get_key('TOKEN-SECRET-KEY'), algorithms=[settings.jwt_algorithm])
        return payload
    except jwt.ExpiredSignatureError:
        return None


def get_azure_ad_client() -> ConfidentialClientApplication:
    """
        Initialize and return Azure AD Client
    """
    azure_ad_client = ConfidentialClientApplication(
        key_vault_manager.get_key("AD-CLIENT-ID"),
        authority=key_vault_manager.get_key("AD-AUTHORITY"),
        client_credential=key_vault_manager.get_key("AD-CLIENT-SECRET"),
    )
    return azure_ad_client


ad_auth_code_flows = RedisDict(redis_client.redis_client, "azure_ad_auth_code_flows", 600)


def get_azure_ad_tokens(auth_code_flow: dict, auth_response: dict) -> tuple[str, str, int]:
    """
        Acquire Azure Access/Refresh Token using Azure Auth response
    """
    azure_ad_client = get_azure_ad_client()
    result = azure_ad_client.acquire_token_by_auth_code_flow(auth_code_flow, auth_response)

    if "access_token" in result and "refresh_token" in result:
        access_token = result["access_token"]
        refresh_token = result["refresh_token"]
        access_token_exp = time.time() + result["expires_in"]
        return access_token, refresh_token, int(access_token_exp)

    raise Exception("Unable to get access token and refresh token from Azure")


def get_azure_ad_tokens_using_refresh_token(refresh_token: str) -> tuple[str, str, int]:
    """
       Acquire Azure Access/Refresh Token using Azure Refresh Token
    """
    azure_ad_client = get_azure_ad_client()
    scope = [key_vault_manager.get_key("AD-CLIENT-ID") + '/.default']
    result = azure_ad_client.acquire_token_by_refresh_token(refresh_token, scopes=scope)

    if "access_token" in result and "refresh_token" in result:
        access_token = result["access_token"]
        refresh_token = result["refresh_token"]
        access_token_exp = time.time() + result["expires_in"]
        return access_token, refresh_token, int(access_token_exp)

    raise Exception("Unable to get access token and refresh token from Azure")
