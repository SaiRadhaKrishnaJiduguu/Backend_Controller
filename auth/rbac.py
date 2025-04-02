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
   
    This module provide utilities related to access management
    
    @author: S. Nair
    @contact: sachin.nair@in.ey.com
"""

from fastapi import Depends, status, Request, WebSocket
from auth import auth
from auth.permissions import get_user_permissions
from core.config import settings
from utils.custom_logging import log
from utils.common import CustomHTTPException


def get_current_user(request: Request):
    """
        Get current user from request
    """
    try:
        access_token = request.cookies.get('access_token')
        if access_token is not None:
            if settings.authentication_basic_enabled:
                decoded_token = auth.decode_token(access_token)
                if decoded_token is None:
                    if settings.authentication_ad_enabled:
                        decoded_token = auth.decode_ad_access_token(access_token)
            elif settings.authentication_ad_enabled:
                decoded_token = auth.decode_ad_access_token(access_token)
            else:
                return None

            return decoded_token['unique_name']
        return None
    except Exception:
        return None


def get_current_user_web_socket(websocket: WebSocket):
    """
        Get current user from websocket
    """
    try:
        access_token = websocket.cookies.get('access_token')
        if access_token is not None:
            if settings.authentication_basic_enabled:
                decoded_token = auth.decode_token(access_token)
                if decoded_token is None:
                    if settings.authentication_ad_enabled:
                        decoded_token = auth.decode_ad_access_token(access_token)
            elif settings.authentication_ad_enabled:
                decoded_token = auth.decode_ad_access_token(access_token)
            else:
                return None

            return decoded_token['unique_name']
        return None
    except Exception:
        return None


class PermissionChecker:
    """
        Class to validate user permission
    """

    def __init__(self, required_permissions: list[str], check_organization: bool = False) -> None:
        self.required_permissions = required_permissions
        self.check_organization = check_organization

    def __call__(self, organization_id: str | None = None, user: str | None = Depends(get_current_user)) -> bool:
        # Get all user permissions
        user_permissions = get_user_permissions(user)
        if self.check_organization:
            if organization_id is not None:
                # if organization needs to be checked
                if organization_id in user_permissions:

                    all_permissions = []

                    for roles_list in user_permissions[organization_id]:
                        for permission_list in roles_list.keys():
                            for permission in roles_list[permission_list]:
                                all_permissions.append(permission['name'])
                    log.debug(all_permissions)
                    for permission in self.required_permissions:
                        if permission not in all_permissions:
                            raise CustomHTTPException(status_code=status.HTTP_401_UNAUTHORIZED, status='error',
                                                      message='Unauthorized')
                else:
                    raise CustomHTTPException(status_code=status.HTTP_401_UNAUTHORIZED, status='error',
                                              message='Unauthorized')
            else:
                log.error('organization_id cannot be empty when check_organization is true')
                raise CustomHTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, status='error',
                                          message='Some error occurred')
        else:
            # if only permission check is required
            all_permissions = []
            for organization in user_permissions.keys():
                for roles_list in user_permissions[organization]:
                    for permission_list in roles_list.keys():
                        for permission in roles_list[permission_list]:
                            all_permissions.append(permission['name'])
            log.debug(all_permissions)
            for permission in self.required_permissions:
                if permission not in all_permissions:
                    raise CustomHTTPException(status_code=status.HTTP_401_UNAUTHORIZED, status='error',
                                              message='Unauthorized')
        return True
