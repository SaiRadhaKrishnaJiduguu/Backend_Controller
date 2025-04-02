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

    API related to access/refresh token

    @author: S. Nair
    @contact: sachin.nair@in.ey.com
"""

from fastapi import APIRouter, Cookie
from fastapi.responses import JSONResponse
from auth import auth
from utils.common import custom_message, system_error_message
from utils.custom_logging import log
from core.config import settings
from core.database_manager import db
from models.models import User

router = APIRouter()


@router.post("/refresh")
async def refresh_access_token(refresh_token: str = Cookie(None)) -> JSONResponse:
    """
        Refresh Access Token using Refresh Token
    """
    try:
        try:
            if settings.authentication_basic_enabled:
                payload = auth.decode_refresh_token(refresh_token)
                if not payload:
                    return custom_message("error", "Invalid refresh token", 401)

                username = payload.get("unique_name")
                if not username:
                    return custom_message("error", "Invalid refresh token", 401)

                with db.create_session() as db_session:
                    user = db_session.query(User).filter(User.username == username).first()

                    if not user:
                        return custom_message("error", "User not found", 401)

                    access_token, expiry_unix = auth.create_access_token(data={
                        "unique_name": user.username
                    })
                    response = custom_message("success", "Access Token Refreshed", 200)
                    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=settings.environment != "local")
                    response.set_cookie(key="access_token_exp", value=str(expiry_unix), httponly=False, secure=settings.environment != "local")
                    return response
            elif settings.authentication_ad_enabled:
                access_token, refresh_token, access_token_exp = auth.get_azure_ad_tokens_using_refresh_token(refresh_token)
                response = custom_message("success", "Login Successful", 200)
                response.set_cookie(key='access_token', value=access_token, httponly=True, secure=settings.environment != "local")
                response.set_cookie(key='refresh_token', value=refresh_token, httponly=True, secure=settings.environment != "local")
                response.set_cookie(key='access_token_exp', value=str(access_token_exp), httponly=False, secure=settings.environment != "local")
                return response
            else:
                log.error('Unable to refresh access as no auth mode is enabled')
                return system_error_message()
        except Exception as exception:
            if settings.authentication_ad_enabled:
                log.debug('Error: %s', exception)
                log.debug('Unable to refresh access token using basic auth. Trying AD refresh token')
                access_token, refresh_token, access_token_exp = auth.get_azure_ad_tokens_using_refresh_token(refresh_token)
                response = custom_message("success", "Login Successful", 200)
                response.set_cookie(key='access_token', value=access_token, httponly=True, secure=settings.environment != "local")
                response.set_cookie(key='refresh_token', value=refresh_token, httponly=True, secure=settings.environment != "local")
                response.set_cookie(key='access_token_exp', value=str(access_token_exp), httponly=False, secure=settings.environment != "local")
                return response
            log.error('Unable to refresh access: %s', exception)
            return system_error_message()

    except Exception as exception:
        log.error('Error: %s', exception)
        return system_error_message()
