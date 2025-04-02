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

    This module defines the routes for Permissions

    @author: S. Nair
    @contact: sachin.nair@in.ey.com
"""

import traceback
from fastapi import APIRouter, status, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import select, insert, delete, exc
from auth.rbac import PermissionChecker
from core.config import settings
from core.database_manager import db
from core.redis_manager import redis_client
from models.models import Permission
from models.schemas import InsertPermission, UpdatePermission
from utils.common import custom_message, system_error_message, resource_not_found_message
from utils.custom_logging import log
from utils.helpers import generate_uuid

router = APIRouter()


@router.get('')
async def get_all_permission(offset: int = 0, limit: int = 10, _: bool = Depends(PermissionChecker(required_permissions=['permission:view']))):
    """
        API to get list of all Permission
    """
    try:
        # Check if limit and offset are valid
        if limit <= 0 or offset < 0:
            log.error('Incorrect offset or limit provided')
            return custom_message("error", 'Unable to process the request. Please check the input provided', 422)

        cache_object = {
            'class': 'Permission',
            'method': 'get_all',
            'offset': offset,
            'limit': limit
        }

        # Get data from cache
        data = redis_client.retrieve_from_cache_hash('Permission', cache_object)

        if data is None:
            log.debug('Cache miss')
            with db.create_session() as db_session:

                stmt = select(Permission).order_by(Permission.name) \
                    .offset(offset).fetch(limit)
                result = db_session.scalars(stmt)
                data = []
                for row in result:
                    data.append({
                        'id': row.id,
                        'name': row.name,
                        'display_name': row.display_name
                    })

                # Add data to cache
                redis_client.add_to_cache_hash('Permission', cache_object, data, settings.redis_cache_ttl_xxl)
                log.debug('Added to cache')

        cache_object = {
            'class': 'Permission',
            'method': 'row_count'
        }

        row_count = redis_client.retrieve_from_cache_hash('Permission', cache_object)

        if row_count is None:
            log.debug('Cache miss')
            row_count = db_session.query(Permission).count()
            redis_client.add_to_cache_hash('Permission', cache_object, row_count, settings.redis_cache_ttl_xxl)
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


@router.get('/{permission_id}')
async def get_permission_details(permission_id, _: bool = Depends(PermissionChecker(required_permissions=['permission:view']))):
    """
        API to get Permission details
    """
    try:

        cache_object = {
            'class': 'Permission',
            'method': 'get',
            'permission_id': permission_id
        }

        data = redis_client.retrieve_from_cache_hash('Permission', cache_object)

        if data is None:
            log.debug('Cache miss')
            with db.create_session() as db_session:

                stmt = select(Permission).where(Permission.id == permission_id)
                result = db_session.scalars(stmt)
                data = None
                for row in result:
                    data = {
                        'id': row.id,
                        'name': row.name,
                        'display_name': row.display_name
                    }

                if not data:
                    return resource_not_found_message()

                redis_client.add_to_cache_hash('Permission', cache_object, data, settings.redis_cache_ttl_xxl)
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


@router.post('')
async def add_new_permission(perm: InsertPermission, _: bool = Depends(PermissionChecker(required_permissions=['permission:create']))):
    """
        API to add new Permission
    """

    try:

        permission_exists = False

        with db.create_session() as db_session:

            stmt = select(Permission).where(Permission.name == perm.name)
            result = db_session.scalars(stmt)
            for _ in result:
                permission_exists = True
                break

        if not permission_exists:

            with db.create_session() as db_session:
                perm_id = generate_uuid()
                stmt = insert(Permission).values(id=perm_id, name=perm.name, display_name=perm.display_name)
                db_session.execute(stmt)
                db_session.commit()

                redis_client.delete_from_cache_hash('Permission')

                response = {
                    'status': 'success',
                    'data': {
                        'id': perm_id
                    }
                }

                return JSONResponse(status_code=status.HTTP_201_CREATED, content=response)

        else:
            return custom_message("error", 'Permission with same name already exists', 422)

    except Exception as exception:
        log.error('Error: %s', exception)
        log.error(traceback.format_exc())
        return system_error_message()


@router.patch('/{permission_id}')
async def update_permission_details(permission_id, perm: UpdatePermission, _: bool = Depends(PermissionChecker(required_permissions=['permission:update']))):
    """
        API to update Permission details
    """
    try:
        permission_exists = False

        with db.create_session() as db_session:
            stmt = select(Permission).where(Permission.id == permission_id)
            result = db_session.scalars(stmt)
            for row in result:
                permission_exists = True
                row.display_name = perm.display_name
                db_session.commit()

        if permission_exists:

            redis_client.delete_from_cache_hash('Permission')
            redis_client.delete_from_cache_hash('UserPermissions')

            response = {
                'status': 'success'
            }

            return JSONResponse(status_code=status.HTTP_200_OK, content=response)

        return resource_not_found_message()

    except Exception as exception:
        log.error('Error: %s', exception)
        log.error(traceback.format_exc())
        return system_error_message()


@router.delete('/{permission_id}')
async def delete_permission_details(permission_id, _: bool = Depends(PermissionChecker(required_permissions=['permission:delete']))):
    """
        API to delete Permission
    """
    try:

        permission_exists = False

        with db.create_session() as db_session:

            stmt = select(Permission).where(Permission.id == permission_id)
            result = db_session.scalars(stmt)
            for _ in result:
                permission_exists = True
                break

        if permission_exists:
            with db.create_session() as db_session:
                stmt = delete(Permission).where(Permission.id == permission_id)
                try:
                    db_session.execute(stmt)
                    db_session.commit()
                except exc.IntegrityError as exception:
                    log.error('Error: %s', exception)
                    log.error(traceback.format_exc())
                    return custom_message("error", 'Cannot delete Permission as there are roles attached to it', 409)

                redis_client.delete_from_cache_hash('Permission')
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
