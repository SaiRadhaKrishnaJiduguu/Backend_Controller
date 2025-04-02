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
    PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
    BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
    TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE USE OR OTHER DEALINGS OF
    THE SOFTWARE AND/OR THE CODES.

    Schemas being used as inputs/dependencies to API

    @author: S. Nair
    @contact: sachin.nair@in.ey.com

"""

from typing import Optional
from pydantic import BaseModel


class UserLoginBasic(BaseModel):
    """
        Schema for login into application via basic mode
    """
    username: str
    password: str


class AzureResponse(BaseModel):
    """
        Schema for response from Azure AD server
    """
    auth_response: dict


class InsertUpdateOrganization(BaseModel):
    """
        Model to insert/update Organization
    """
    name: str


class InsertUpdateBusinessFunction(BaseModel):
    """
        Model to insert/update business function
    """
    name: str


class InsertSkill(BaseModel):
    """
        Model to insert/update skill
    """
    name: str
    organizations: list[str]
    template: dict


class UpdateSkill(BaseModel):
    """
        Model to update skill
    """
    name: Optional[str] = None
    organizations: Optional[list[str]] = None


class InsertCustomSkill(BaseModel):
    """
        Model to insert/update skill
    """
    name: str
    skill_id: str
    template_data: dict


class UpdateCustomSkill(BaseModel):
    """
        Model to insert/update skill
    """
    name: Optional[str] = None
    template_data: Optional[dict] = None


class QueryResponse(BaseModel):
    """
        Model to return response for query
    """
    chat_id: str
    query_id: str
    response: str


class InsertPermission(BaseModel):
    """
        Model to insert permission
    """
    name: str
    display_name: str


class UpdatePermission(BaseModel):
    """
        Model to update permission
    """
    display_name: str


class InsertRole(BaseModel):
    """
        Model to insert role
    """
    name: str
    permissions: list


class UpdateRole(BaseModel):
    """
        Model to update role
    """
    name: Optional[str] = None
    permissions: Optional[list] = []


class UpdateDocument(BaseModel):
    """
        Model to update document
    """
    display_name: str


class DeleteDocuments(BaseModel):
    """
        Model to delete documents
    """

    file_ids: list
