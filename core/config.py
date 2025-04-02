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

    Configuration being used across the project

    @author: S. Nair
    @contact: sachin.nair@in.ey.com
"""

import os


class Settings:
    """
        Project Settings
    """
    project_name = 'Counter The Counterfeit'
    project_name_short = 'CTC'  # Make sure no space in the short name
    environment = 'production'  # Valid options are 'local', 'staging' and 'production'
    allowed_origins = []
    allowed_credentials = False
    authentication_modes = []  # Valid options are 'basic', 'ad' and 'all'
    authentication_basic_enabled = False
    authentication_ad_enabled = False
    basic_authentication_max_invalid_login_attempts = 3  # Only required if basic authentication is enabled
    access_token_expiry = 60 * 24  # 24 hours (in minutes) only applicable for basic authentication
    refresh_token_expiry = 60 * 24 * 7  # 7 days (in minutes) only applicable for basic authentication
    jwt_algorithm = "HS512"  # only applicable for basic authentication
    db_connection_pool_size = 5
    db_connection_max_overflow = 0
    redis_pool_size = 5
    redis_cache_ttl_s = 300  # 5 min
    redis_cache_ttl_m = 1800  # 30 Min
    redis_cache_ttl_l = 3600  # 1 Hrs
    redis_cache_ttl_xl = 43200  # 12 Hrs
    redis_cache_ttl_xxl = 86400  # 24 Hrs

    def __init__(self) -> None:
        """
                    Initiate Project Settings
                """
        # Set the project environment
        project_environment_env_variable = self.project_name_short + '_PROJECT_ENVIRONMENT'
        project_environment = os.getenv(project_environment_env_variable)

        if project_environment is None:
            raise ValueError(f'{project_environment_env_variable} environment variable is not set.')

        if project_environment.lower() not in ['local', 'staging', 'production']:
            raise ValueError(f'Invalid value set for {project_environment_env_variable}.')

        self.environment = project_environment.lower()

        # Set the allowed credentials
        if self.environment in ['local', 'staging']:
            self.allowed_credentials = True

        # Set the allowed origins
        allowed_origins_env_variable = self.project_name_short + '_ALLOWED_ORIGINS'
        allowed_origins = os.getenv(allowed_origins_env_variable)

        if allowed_origins is None:
            raise ValueError(f'{allowed_origins_env_variable} environment variable is not set.')

        for origin in allowed_origins.split(','):
            self.allowed_origins.append(origin)

        # Set the authentication mode
        authentication_modes_env_variable = self.project_name_short + '_AUTHENTICATION_MODES'
        authentication_modes = os.getenv(authentication_modes_env_variable)

        if authentication_modes is None:
            raise ValueError(f'{authentication_modes_env_variable} environment variable is not set.')

        for mode in authentication_modes.split(','):
            if mode.lower() not in ['basic', 'ad', 'all']:
                raise ValueError(f'Invalid value set for {authentication_modes}.')
            self.authentication_modes.append(mode.lower())

        if 'basic' in self.authentication_modes or 'all' in self.authentication_modes:
            self.authentication_basic_enabled = True

        if 'ad' in self.authentication_modes or 'all' in self.authentication_modes:
            self.authentication_ad_enabled = True


settings = Settings()
