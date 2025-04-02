"""
    Copyright 2020-2024 AND Confidential Information of EY LLP. All rights reserved.
    Only authorised EY LLP employees and authorised contractors may utilise the software or codes
    (in source and binary forms, with or without modification) subject to the following conditions:
    * Only in performance of work for EY LLP;
    * NO licence is granted to any party not so authorised;
    * The above copyright notice and this Permission notice shall be included in all copies or
    substantial portions of the software.

    THE SOFTWARE AND/OR THE CODES ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
    PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
    LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE USE OR OTHER DEALINGS
    OF THE SOFTWARE AND/OR THE CODES.

    This module provide utilities related to permissions

    @author: S. Nair
    @contact: sachin.nair@in.ey.com
"""

from utils.custom_logging import log
from core.database_manager import db
from core.redis_manager import redis_client
from core.config import settings
from models.models import UserRoleAssociation, Roles, Permission, RolesPermissionAssociation


def get_user_permissions(username):
    """
        Get all user Permission
    """

    cache_object = {
        'class': 'UserRoleAssociation,Roles',
        'method': 'get_user_roles',
        'user': username
    }

    roles_organization_list = redis_client.retrieve_from_cache_hash('UserPermissions', cache_object)

    # Get Roles and organization for a user
    if roles_organization_list is None:
        log.debug('Cache miss')
        with db.create_session() as db_session:
            roles_result = db_session.query(UserRoleAssociation.roles_id,
                                            Roles.organization_id) \
                .join(Roles, UserRoleAssociation.roles_id == Roles.id,
                      isouter=True).where(
                UserRoleAssociation.user_username == username)
            roles_organization_list = []
            for row in roles_result:
                roles_organization_list.append((row.roles_id, row.organization_id))

            redis_client.add_to_cache_hash('UserPermissions', cache_object, roles_organization_list, settings.redis_cache_ttl_xxl)
            log.debug('Added to cache')

    cache_object = {
        'class': 'RolesPermissionAssociation,Permission',
        'method': 'get_user_permissions',
        'roles_id': username
    }
    user_permissions = redis_client.retrieve_from_cache_hash('UserPermissions', cache_object)

    if user_permissions is None:
        with db.create_session() as db_session:
            log.debug('Cache miss')
            user_permissions = {}
            # Get user permissions for each role in organization
            for role_organization in roles_organization_list:

                if role_organization[1] not in roles_organization_list:
                    user_permissions[role_organization[1]] = []

                    roles_list = []

                    permissions_result = db_session.query(Permission.id, Permission.name, Permission.display_name).join(
                        RolesPermissionAssociation, RolesPermissionAssociation.permission_id == Permission.id,
                        isouter=True).where(
                        RolesPermissionAssociation.roles_id == role_organization[0])

                    for permissions in permissions_result:
                        roles_list.append({
                            'id': permissions.id,
                            'name': permissions.name,
                            'display_name': permissions.display_name
                        })

                    if len(roles_list) > 0:
                        user_permissions[role_organization[1]].append({
                            role_organization[0]: roles_list
                        })

            redis_client.add_to_cache_hash('UserPermissions', cache_object, user_permissions, settings.redis_cache_ttl_xxl)
            log.debug('Added to cache')

    return user_permissions
