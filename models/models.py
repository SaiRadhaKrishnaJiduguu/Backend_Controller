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

    DB Models for the project

    @author: S. Nair
    @contact: sachin.nair@in.ey.com

"""

from sqlalchemy import Column, String, DateTime, Boolean, Integer, ForeignKey, Text
from sqlalchemy.orm import declarative_base, mapped_column, relationship

Base = declarative_base()


class AuthenticationModes(Base):
    """
        Class for authentication_modes db table
    """

    __tablename__ = 'authentication_modes'

    modes = Column(String(100), primary_key=True, nullable=False)


class Organization(Base):
    """
        Class for organization db table
    """

    __tablename__ = 'organization'

    id = Column(String(36), primary_key=True, nullable=False)
    name = Column(Text, nullable=False)
    date_added = Column(DateTime, nullable=False)


class Permission(Base):
    """
        Class for permission db table
    """

    __tablename__ = 'permission'

    id = Column(String(36), primary_key=True, nullable=False)
    name = Column(Text, nullable=False)
    display_name = Column(Text, nullable=False)


class Roles(Base):
    """
        Class for roles db table
    """

    __tablename__ = 'roles'

    id = Column(String(36), primary_key=True, nullable=False)
    name = Column(Text, nullable=False)
    organization_id = Column(String(36), ForeignKey('organization.id'), nullable=False)
    can_edit = Column(Boolean, nullable=False)
    can_delete = Column(Boolean, nullable=False)
    date_added = Column(DateTime, nullable=False)
    roles_permission_association = relationship("RolesPermissionAssociation")


class RolesPermissionAssociation(Base):
    """
        Class for roles_permission_association db table
    """

    __tablename__ = 'roles_permission_association'

    id = Column(String(36), primary_key=True, nullable=False)
    roles_id = Column(String(36), ForeignKey('roles.id'), nullable=False)
    permission_id = Column(String(36), ForeignKey('permission.id'), nullable=False)
    permission = relationship("Permission")


class User(Base):
    """
        Class for user db table
    """

    __tablename__ = 'user'

    username = Column(String(200), primary_key=True, nullable=False)
    password = Column(String(200), nullable=True)
    last_login_timestamp = Column(DateTime, nullable=True)
    active = Column(Boolean, nullable=False)
    invalid_login_attempts = Column(Integer, nullable=False)
    date_added = Column(DateTime, nullable=False)
    date_modified = Column(DateTime, nullable=False)
    authentication_mode = mapped_column(ForeignKey("authentication_modes.modes"))

    organizations = relationship(
        "Organization",
        secondary="user_organization_association",
    )


class UserOrganizationAssociation(Base):
    """
        Class for user_organization_association db table
    """

    __tablename__ = 'user_organization_association'

    id = Column(String(36), primary_key=True, nullable=False)
    user_username = Column(String(200), ForeignKey('user.username'), nullable=False)
    organization_id = Column(String(36), ForeignKey('organization.id'), nullable=False)


class UserRoleAssociation(Base):
    """
        Class for user_role_association db table
    """

    __tablename__ = 'user_role_association'

    id = Column(String(36), primary_key=True, nullable=False)
    user_username = Column(String(200), ForeignKey('user.username'), nullable=False)
    roles_id = Column(String(36), ForeignKey('roles.id'), nullable=False)
