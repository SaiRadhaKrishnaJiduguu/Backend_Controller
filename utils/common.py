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

    Common utility being used across the project

    @author: S. Nair
    @contact: sachin.nair@in.ey.com

"""

from http import HTTPStatus
from fastapi import status as http_status
from fastapi.responses import JSONResponse
from utils.custom_logging import log


def system_error_message() -> JSONResponse:
    """
        Generate a generic system error message.

        This function returns a JSON response indicating a generic system error,
        suitable for use in API responses.
    """
    response = {
        'status': 'error',
        'message': 'Some error occurred'
    }

    return JSONResponse(status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR, content=response)


def unauthorized_message() -> JSONResponse:
    """
        Generate a generic unauthorized message.
    """
    response = {
        'status': 'error',
        'message': 'Unauthorized'
    }

    return JSONResponse(status_code=http_status.HTTP_401_UNAUTHORIZED, content=response)


def resource_not_found_message() -> JSONResponse:
    """
        Generate a generic resource not found message.
    """
    response = {
        'status': 'error',
        'message': 'The requested resource was not found in the server'
    }

    return JSONResponse(status_code=http_status.HTTP_404_NOT_FOUND, content=response)


def custom_message(status: str, message: str, status_code: int) -> JSONResponse:
    """
            Generate a generic response message.
    """

    response = {
        'status': status,
        'message': message
    }

    try:
        # Get the HTTP status description
        http_status_code = HTTPStatus(status_code)
        # Construct the constant name in the fastapi.status module
        status_constant = f"HTTP_{status_code}_{http_status_code.name}"
        # Get the constant value from the status module
        status_code = getattr(http_status, status_constant)
    except ValueError:
        log.info("Unsupported status code: %s", status_code)
        return system_error_message()

    return JSONResponse(status_code=status_code, content=response)


class CustomHTTPException(Exception):
    """
        Custom HTTP exception class
    """

    def __init__(self, status_code: int, status: str, message: str):
        self.status_code = status_code
        self.status = status
        self.message = message
