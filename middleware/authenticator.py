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
    PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
    BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE USE OR OTHER DEALINGS OF
    THE SOFTWARE AND/OR THE CODES.

    Authenticator middleware to authenticate each request

    @author: S. Nair
    @contact: sachin.nair@in.ey.com

"""
import time
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from auth import auth
from core.config import settings
from utils.common import unauthorized_message
from utils.custom_logging import log


class AuthMiddleware(BaseHTTPMiddleware):
    """
        Class to validate auth token before each request
    """
    white_listed_url = [
        '/login/basic',
        '/login/ad/auth-url',
        '/login/ad/token',
        '/token/refresh',
        '/health',
    ]

    async def dispatch(self, request: Request, call_next):
        """
            Dispatch method to process each request.
        """
        # ignore whitelisted url from token validation
        for part_url in self.white_listed_url:
            if part_url in str(request.url):
                response = await call_next(request)
                return response
        # get token from cookies
        access_token = request.cookies.get('access_token')
        refresh_token = request.cookies.get('refresh_token')
        # if auth token not present
        if access_token is None or refresh_token is None:
            # return unauthorized message
            response = unauthorized_message()
            return response

        try:

            if settings.authentication_basic_enabled:
                # Validate access token
                decoded_token = auth.decode_token(access_token)
                if decoded_token is None:
                    if settings.authentication_ad_enabled:
                        decoded_token = auth.decode_ad_access_token(access_token)
                    else:
                        response = unauthorized_message()
                        return response
                access_token_expiry_time = decoded_token.get('exp')
                if access_token_expiry_time > time.time():
                    # access_token is valid
                    response = await call_next(request)
                    return response
            elif settings.authentication_ad_enabled:
                decoded_token = auth.decode_ad_access_token(access_token)
                access_token_expiry_time = decoded_token.get('exp')
                if access_token_expiry_time > time.time():
                    # access_token is valid
                    response = await call_next(request)
                    return response
            else:
                log.error('Unable to verify access token as no auth mode is enabled')
                response = await call_next(request)
                return response

        except Exception as exception:
            log.error(exception)
        response = unauthorized_message()
        return response
