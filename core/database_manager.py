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

    Database utility to connect to DB

    @author: S. Nair
    @contact: sachin.nair@in.ey.com
"""

import contextlib
from urllib.parse import quote_plus
from sqlalchemy import create_engine
from sqlalchemy.exc import DatabaseError, SQLAlchemyError
from sqlalchemy.orm import sessionmaker as sa_sessionmaker, scoped_session
from core import key_vault_manager
from core.config import settings
from utils.custom_logging import log


class Database:
    """
        Database class
    """

    global_session = None

    def __init__(self) -> None:
        """
            Initialize database connection string and engine
        """
        db_server_name = key_vault_manager.get_key('DB-SERVER-NAME')
        db_name = key_vault_manager.get_key('DB-NAME')
        db_port = key_vault_manager.get_key('DB-PORT')
        db_username = key_vault_manager.get_key('DB-USERNAME')
        db_password = quote_plus(key_vault_manager.get_key('DB-PASSWORD'))
        db_engine_conn_url = f'mssql+pymssql://{db_username}:{db_password}@{db_server_name}:{db_port}/{db_name}?charset=utf8'

        engine = create_engine(db_engine_conn_url,
                               pool_size=settings.db_connection_pool_size,
                               max_overflow=settings.db_connection_max_overflow, pool_pre_ping=True)

        session_factory = sa_sessionmaker(bind=engine)
        self.global_session = scoped_session(session_factory)

        log.info('Sqlalchemy DB engine initialized')

    @contextlib.contextmanager
    def create_session(self) -> scoped_session:
        """
            create new session using the global session
        """
        session = self.global_session()

        try:
            yield session
            session.commit()
        except DatabaseError as exception:
            log.error("Session rolled back due to error: %s", str(exception))
            session.rollback()
            raise
        except SQLAlchemyError as exception:
            log.error("Session rolled back due to error: %s", str(exception))
            session.rollback()
            raise


db = Database()
