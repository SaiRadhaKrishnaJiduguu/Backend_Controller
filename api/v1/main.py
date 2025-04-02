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

    FastAPI Sub App for api/v1 path

    @author: S. Nair
    @contact: sachin.nair@in.ey.com
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.v1.routes import health, login
from core.config import settings
from middleware.authenticator import AuthMiddleware

if settings.environment == 'production':
    app_v1 = FastAPI(
        title=settings.project_name,
        openapi_url=None,
        docs_url=None,
        redoc_url=None
    )
else:
    app_v1 = FastAPI(title=settings.project_name)

app_v1.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=settings.allowed_credentials,
    allow_methods=['*'],
    allow_headers=['*'],
)

app_v1.include_router(health.router, prefix='/health')
app_v1.include_router(login.router, prefix='/login')

app_v1.add_middleware(AuthMiddleware)
