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

    This module provides a logger setup for custom logging.

    @author: S. Nair
    @contact: sachin.nair@in.ey.com

"""

import sys
import os
import logging
from logging import Logger

from core.config import settings

PROJECT_ROOT_PATH = None


class LogFilter(logging.Filter):
    """
        Log filter to get module path
    """

    def filter(self, record: logging.LogRecord) -> bool:
        file_path = record.pathname
        record.pathname = os.path.relpath(file_path, PROJECT_ROOT_PATH)
        return True


def get_logger() -> Logger:
    """
        Returns logger to log into azure terminal
    """
    logger = logging.getLogger('gunicorn.error')
    logging_level = logging.INFO
    env_logging_level = os.getenv(settings.project_name_short + '_LOGGING_LEVEL')
    if env_logging_level:
        env_logging_level = env_logging_level.upper().strip()

    if env_logging_level in ['DEBUG', 'WARNING', 'ERROR']:
        if env_logging_level == 'DEBUG':
            logging_level = logging.DEBUG
        elif env_logging_level == 'WARNING':
            logging_level = logging.WARNING
        else:
            logging_level = logging.ERROR

    logger.setLevel(logging_level)

    if not logger.hasHandlers():
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter('%(asctime)s %(levelname)s %(pathname)s:%(lineno)d - %(message)s')
        handler.addFilter(LogFilter())
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    logger.info("Logger %s initialized with level %s", settings.project_name_short, logging.getLevelName(logging_level))
    return logger


log = get_logger()
