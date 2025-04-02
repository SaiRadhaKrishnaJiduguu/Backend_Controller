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

    FastAPI Main File

    @author: S. Nair
    @contact: sachin.nair@in.ey.com

"""

import os


from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from core.config import settings
from core import key_vault_manager
from api.v1.main import app_v1
from api.v1.routes import health
from utils import custom_logging
from utils.common import CustomHTTPException

# Initialize the logger
custom_logging.PROJECT_ROOT_PATH = os.path.dirname(os.path.abspath(__file__))

if settings.environment == 'production':
    app = FastAPI(
        title=settings.project_name,
        openapi_url=None,
        docs_url=None,
        redoc_url=None
    )
else:
    app = FastAPI(title=settings.project_name)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=settings.allowed_credentials,
    allow_methods=['*'],
    allow_headers=['*'],
)


def exception_handler(fast_app: FastAPI):
    """
        Exception handler for custom exceptions
    """

    @fast_app.exception_handler(CustomHTTPException)
    async def custom_http_exception_handler(_: Request, exc: CustomHTTPException):
        response = {
            'status': exc.status,
            'message': exc.message
        }
        return JSONResponse(status_code=exc.status_code, content=response)


exception_handler(app)
exception_handler(app_v1)

app.include_router(health.router, prefix='/health')
app.mount('/api/v1', app_v1)
key_vault_manager.validate_all_keys()
