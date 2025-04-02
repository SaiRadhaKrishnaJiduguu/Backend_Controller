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

    API related to login

    @author: S. Nair
    @contact: sachin.nair@in.ey.com
"""

from datetime import datetime
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from fastapi import status as http_status
from auth import auth
from auth.auth import decode_ad_access_token
from core import key_vault_manager
from core.config import settings
from core.database_manager import db
from models import schemas
from models.models import User
from utils.common import unauthorized_message, custom_message, system_error_message
from utils.custom_logging import log
from utils.helpers import dict_to_str, str_to_dict, generate_uuid

router = APIRouter()


@router.post('/basic')
async def login_basic(user_details: schemas.UserLoginBasic) -> JSONResponse:
    """
        Login using username and password
    """
    try:

        if not settings.authentication_basic_enabled:
            log.error("Basic authentication is not enabled in the environment settings")
            return custom_message("error", "Service Unavailable", 503)

        with db.create_session() as db_session:
            user = db_session.query(User).filter(User.username == user_details.username).first()

            if user is None:
                return custom_message("error", "Invalid username/password provided", 401)

            if user.authentication_mode.lower() != "basic":
                return custom_message("error", "Invalid login type. Use the login type used while account creation", 405)

            if not user.active:
                return custom_message("error", "User Locked. Please contact admin", 401)

            if not auth.verify_password(user_details.password, user.password):
                user.invalid_login_attempts += 1
                db_session.commit()
                if user.invalid_login_attempts >= settings.basic_authentication_max_invalid_login_attempts:
                    user.active = False
                    return custom_message("error", "User Locked. Please contact admin", 401)

                return custom_message("error", "Invalid username/password provided", 401)

            user.invalid_login_attempts = 0
            user.last_login_timestamp = datetime.utcnow()
            db_session.commit()
            db_session.refresh(user)
            access_token, expiry_unix = auth.create_access_token(data={
                "unique_name": user.username,
            })

            refresh_token = auth.create_refresh_token(data={
                "unique_name": user.username
            })

            response = custom_message("success", "Login Successful", 200)
            response.set_cookie(key="access_token", value=access_token, httponly=True, secure=settings.environment != "local")
            response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=settings.environment != "local")
            response.set_cookie(key="access_token_exp", value=str(expiry_unix), httponly=False, secure=settings.environment != "local")
            return response
    except Exception as exception:
        log.error('Error: %s', exception)
        return system_error_message()


@router.get("/ad/auth-url")
async def get_auth_url() -> JSONResponse:
    """
        Get Azure AD redirect url
    """
    try:
        if not settings.authentication_ad_enabled:
            log.error("AD authentication is not enabled in the environment settings")
            return custom_message("error", "Service Unavailable", 503)

        state = generate_uuid()
        azure_ad_client = auth.get_azure_ad_client()
        scope = [key_vault_manager.get_key("AD-CLIENT-ID") + '/.default']
        auth_code_flow = azure_ad_client.initiate_auth_code_flow(scope, redirect_uri=key_vault_manager.get_key("AD-REDIRECT-URI"), state=state)
        auth.ad_auth_code_flows[state] = dict_to_str(auth_code_flow)

        response = {
            'status': "success",
            'auth_url': auth_code_flow["auth_uri"]
        }

        return JSONResponse(status_code=http_status.HTTP_200_OK, content=response)
    except Exception as exception:
        log.error('Error: %s', exception)
        return system_error_message()


@router.post('/ad/token')
async def fetch_azure_ad_access_token(resp: schemas.AzureResponse) -> JSONResponse:
    """
        Get Azure AD token using code
    """
    try:

        if not settings.authentication_ad_enabled:
            log.error("AD authentication not enabled in the environment settings")
            return custom_message("error", "Service Unavailable", 503)

        auth_code_flow = str_to_dict(auth.ad_auth_code_flows[resp.auth_response["state"]])
        if auth_code_flow is None:
            return unauthorized_message()
        access_token, refresh_token, access_token_exp = auth.get_azure_ad_tokens(auth_code_flow, resp.auth_response)

        decoded_access_token = decode_ad_access_token(access_token)
        username = decoded_access_token['unique_name']

        with db.create_session() as db_session:
            user = db_session.query(User).filter(User.username == username).first()

            if user is None:
                return custom_message("error", "User is not registered. Please contact admin", 401)

            if user.authentication_mode.lower() != "ad":
                return custom_message("error", "Invalid login type. Use the login type used while account creation", 405)

            if not user.active:
                return custom_message("error", "User Locked. Please contact admin", 401)

            user.last_login_timestamp = datetime.utcnow()
            db_session.commit()
            db_session.refresh(user)

        response = custom_message("success", "Login Successful", 200)
        response.set_cookie(key='access_token', value=access_token, httponly=True, secure=settings.environment != "local")
        response.set_cookie(key='refresh_token', value=refresh_token, httponly=True, secure=settings.environment != "local")
        response.set_cookie(key='access_token_exp', value=str(access_token_exp), httponly=False, secure=settings.environment != "local")
        return response
    except Exception as exception:
        log.error('Error: %s', exception)
        return system_error_message()
