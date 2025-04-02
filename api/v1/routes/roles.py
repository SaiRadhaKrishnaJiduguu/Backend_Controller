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

    This module defines the routes for Roles

    @author: S. Nair
    @contact: sachin.nair@in.ey.com
"""
import traceback
from datetime import datetime

from fastapi.responses import JSONResponse
from fastapi import APIRouter, status, Depends
from sqlalchemy import select, insert, delete, exc, and_
from auth.rbac import PermissionChecker
from core.config import settings
from core.database_manager import db
from core.redis_manager import redis_client
from models.models import Roles, Permission, RolesPermissionAssociation
from models.schemas import InsertRole, UpdateRole
from utils.common import custom_message, system_error_message, resource_not_found_message
from utils.custom_logging import log
from utils.helpers import generate_uuid

# Router for /organization/roles
router_organization = APIRouter()


@router_organization.get('')
async def get_all_roles_in_organization(organization_id, offset: int = 0, limit: int = 10, _: bool = Depends(PermissionChecker(required_permissions=['roles:view'], check_organization=True))):
    """
        API to get list of all roles
    """
    try:

        # Check if limit and offset are valid
        if limit <= 0 or offset < 0:
            log.error('Incorrect offset or limit provided')
            return custom_message("error", 'Unable to process the request. Please check the input provided', 422)

        cache_object = {
            'class': 'Roles',
            'method': 'get_all',
            'organization_id': organization_id,
            'offset': offset,
            'limit': limit
        }

        # Get data from cache
        data = redis_client.retrieve_from_cache_hash(organization_id + '_roles', cache_object)

        if data is None:
            log.debug('Cache miss')
            with db.create_session() as db_session:

                stmt = select(Roles).where(Roles.organization_id == organization_id).order_by(Roles.date_added) \
                    .offset(offset).fetch(limit)

                result = db_session.scalars(stmt)
                data = []
                for row in result:
                    roles_permission_association_list = row.roles_permission_association
                    role_permissions = []
                    for role_permission in roles_permission_association_list:
                        permission = role_permission.permission
                        role_permissions.append({
                            'id': permission.id,
                            'name': permission.name,
                            'display_name': permission.display_name
                        })
                    data.append({
                        'id': row.id,
                        'name': row.name,
                        'can_edit': row.can_edit,
                        'can_delete': row.can_delete,
                        'permissions': role_permissions,
                        'date_added': row.date_added.isoformat()
                    })

                # Add data to cache
                redis_client.add_to_cache_hash(organization_id + '_roles', cache_object, data, settings.redis_cache_ttl_xxl)
                log.debug('Added to cache')

        cache_object = {
            'class': 'Roles',
            'method': 'row_count',
            'organization_id': organization_id
        }

        row_count = redis_client.retrieve_from_cache_hash(organization_id + '_roles', cache_object)

        if row_count is None:
            log.debug('Cache miss')
            row_count = db_session.query(Roles).where(Roles.organization_id == organization_id).count()
            redis_client.add_to_cache_hash(organization_id + '_roles', cache_object, row_count, settings.redis_cache_ttl_xxl)
            log.debug('Added to cache')

        response = {
            'status': 'success',
            'data': data,
            'count': row_count
        }

        return JSONResponse(status_code=status.HTTP_200_OK, content=response)
    except Exception as exception:
        log.error('Error: %s', exception)
        log.error(traceback.format_exc())
        return system_error_message()


@router_organization.get('/{role_id}')
async def get_role_details(organization_id, role_id, _: bool = Depends(PermissionChecker(required_permissions=['roles:view'], check_organization=True))):
    """
        API to get organization details
    """
    try:

        cache_object = {
            'class': 'organization',
            'method': 'get',
            'role_id': role_id
        }

        data = redis_client.retrieve_from_cache_hash('Roles', cache_object)

        if data is None:
            log.debug('Cache miss')
            with db.create_session() as db_session:

                stmt = select(Roles).where(and_(Roles.id == role_id, Roles.organization_id == organization_id))
                result = db_session.scalars(stmt)
                data = None
                for row in result:
                    roles_permission_association_list = row.roles_permission_association
                    role_permissions = []
                    for role_permission in roles_permission_association_list:
                        permission = role_permission.permission
                        role_permissions.append({
                            'id': permission.id,
                            'name': permission.name,
                            'display_name': permission.display_name
                        })

                    data = {
                        'id': row.id,
                        'name': row.name,
                        'can_edit': row.can_edit,
                        'can_delete': row.can_delete,
                        'permissions': role_permissions,
                        'date_added': row.date_added.isoformat()
                    }

                if not data:
                    return resource_not_found_message()

                redis_client.add_to_cache_hash('Roles', cache_object, data, settings.redis_cache_ttl_xxl)
                log.debug('Added to cache')

        response = {
            'status': 'success',
            'data': data
        }

        return JSONResponse(status_code=status.HTTP_200_OK, content=response)

    except Exception as exception:
        log.error('Error: %s', exception)
        log.error(traceback.format_exc())
        return system_error_message()


@router_organization.post('')
async def add_new_role(organization_id, new_role: InsertRole, _: bool = Depends(PermissionChecker(required_permissions=['roles:create'], check_organization=True))):
    """
        API to add new role
    """

    try:

        role_exists = False

        with db.create_session() as db_session:

            stmt = select(Roles).where(Roles.name == new_role.name and Roles.organization_id == organization_id)
            result = db_session.scalars(stmt)
            for _ in result:
                role_exists = True
                break

        if not role_exists:
            all_permission_exists = True

            with db.create_session() as db_session:
                for perm_id in new_role.permissions:
                    stmt = select(Permission).where(Permission.id == perm_id)
                    result = db_session.scalars(stmt)
                    result_len = 0
                    for _ in result:
                        result_len += 1

                    if result_len == 0:
                        all_permission_exists = False
                        break

            if not all_permission_exists:
                return custom_message("error", 'Invalid permission id provided', 400)

            with db.create_session() as db_session:
                role_id = generate_uuid()
                stmt = insert(Roles).values(id=role_id, name=new_role.name, organization_id=organization_id, can_edit=True, can_delete=True, date_added=datetime.utcnow())
                db_session.execute(stmt)
                for perm_id in new_role.permissions:
                    stmt = insert(RolesPermissionAssociation).values(id=generate_uuid(), roles_id=role_id, permission_id=perm_id)
                    db_session.execute(stmt)

                db_session.commit()

                redis_client.delete_from_cache_hash(organization_id + '_roles')

                response = {
                    'status': 'success',
                    'data': {
                        'id': role_id
                    }
                }

                return JSONResponse(status_code=status.HTTP_201_CREATED, content=response)

        else:
            return custom_message("error", 'Role with same name already exists', 422)
    except Exception as exception:
        log.error('Error: %s', exception)
        log.error(traceback.format_exc())
        return system_error_message()


@router_organization.patch('/{role_id}')
async def update_role_details(organization_id, role_id, updated_role: UpdateRole, _: bool = Depends(PermissionChecker(required_permissions=['roles:update'], check_organization=True))):
    """
        API to update roles
    """
    try:

        new_name_already_exists = False

        if updated_role.name:

            with db.create_session() as db_session:

                stmt = select(Roles).where(and_(Roles.name == updated_role.name, Roles.organization_id == organization_id))
                result = db_session.scalars(stmt)
                for _ in result:
                    new_name_already_exists = True
                    break

        all_permission_exists = True

        if updated_role.permissions:

            with db.create_session() as db_session:
                for perm_id in updated_role.permissions:
                    stmt = select(Permission).where(Permission.id == perm_id)
                    result = db_session.scalars(stmt)
                    result_len = 0
                    for _ in result:
                        result_len += 1

                    if result_len == 0:
                        all_permission_exists = False
                        break

        if not all_permission_exists:
            return custom_message("error", 'Invalid permission id provided', 400)

        role_exists = False

        with db.create_session() as db_session:

            stmt = select(Roles).where(and_(Roles.id == role_id, Roles.organization_id == organization_id))
            result = db_session.scalars(stmt)
            for row in result:
                role_exists = True
                if not new_name_already_exists:
                    if updated_role.name:
                        row.name = updated_role.name
                    if updated_role.permissions:
                        roles_permission_association_list = row.roles_permission_association
                        current_permissions = []
                        for role_permission in roles_permission_association_list:
                            permission = role_permission.permission
                            current_permissions.append(permission.id)

                        permissions_to_delete = current_permissions.copy()
                        permissions_to_add = []
                        for perm_id in updated_role.permissions:
                            if perm_id in current_permissions:
                                permissions_to_delete.remove(perm_id)
                            else:
                                permissions_to_add.append(perm_id)

                        for perm_id in permissions_to_add:
                            stmt = insert(RolesPermissionAssociation).values(id=generate_uuid(), roles_id=role_id, permission_id=perm_id)
                            db_session.execute(stmt)

                        for perm_id in permissions_to_delete:
                            stmt = delete(RolesPermissionAssociation).where(and_(RolesPermissionAssociation.roles_id == role_id, RolesPermissionAssociation.permission_id == perm_id))
                            db_session.execute(stmt)

                    db_session.commit()

        if role_exists:

            if not new_name_already_exists:
                if updated_role.name or updated_role.permissions:
                    redis_client.delete_from_cache_hash(organization_id + '_roles')
                    redis_client.delete_from_cache_hash('UserPermissions')

                    response = {
                        'status': 'success'
                    }

                    return JSONResponse(status_code=status.HTTP_200_OK, content=response)

                return custom_message("error", 'Either name or permission list needs to be provided', 400)

            return custom_message("error", 'Roles with same name already exists', 422)

        return resource_not_found_message()

    except Exception as exception:
        log.error('Error: %s', exception)
        log.error(traceback.format_exc())
        return system_error_message()


@router_organization.delete('/{role_id}')
async def delete_role_details(organization_id, role_id, _: bool = Depends(PermissionChecker(required_permissions=['roles:delete'], check_organization=True))):
    """
        API to delete roles
    """
    try:

        roles_exists = False

        with db.create_session() as db_session:

            stmt = select(Roles).where(and_(Roles.id == role_id, Roles.organization_id == organization_id))
            result = db_session.scalars(stmt)
            for _ in result:
                roles_exists = True
                break

        if roles_exists:
            with db.create_session() as db_session:

                stmt = delete(RolesPermissionAssociation).where(RolesPermissionAssociation.roles_id == role_id)
                db_session.execute(stmt)
                stmt = delete(Roles).where(and_(Roles.id == role_id, Roles.organization_id == organization_id))
                try:
                    db_session.execute(stmt)
                except exc.IntegrityError as exception:
                    log.error('Error: %s', exception)
                    log.error(traceback.format_exc())
                    log.error('Cannot delete Role as there are users attached to it')
                    return custom_message("error", 'Cannot delete Role as there are users attached to it', 409)
                db_session.commit()
                redis_client.delete_from_cache_hash(organization_id + '_roles')
                redis_client.delete_from_cache_hash('UserPermissions')

                response = {
                    'status': 'success'
                }

                return JSONResponse(status_code=status.HTTP_200_OK, content=response)
        else:
            return resource_not_found_message()
    except Exception as exception:
        log.error('Error: %s', exception)
        log.error(traceback.format_exc())
        return system_error_message()
