# -*- coding: utf-8 -*-
# Copyright 2022 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Turbinia API client command-line tool."""

import logging
import os
import sys

from google_auth_oauthlib import flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google.auth import exceptions as google_exceptions

log = logging.getLogger(__name__)


def get_oauth2_token_id(credentials_path, client_secrets_path):
  """Authenticates the user using Google OAuth and get ID Token."""
  scopes = ['openid', 'https://www.googleapis.com/auth/userinfo.email']
  credentials = None

  # Load credentials file if it exists
  if os.path.exists(credentials_path):
    try:
      credentials = Credentials.from_authorized_user_file(
          credentials_path, scopes)
    except ValueError as exception:
      log.error(f'Error loading credentials: {exception!s}')
    # Refresh credentials using existing refresh_token
    if credentials and credentials.refresh_token:
      log.debug('Found a refresh token. Requesting new id_token..')
      try:
        credentials.refresh(Request())
      except google_exceptions.RefreshError as exception:
        log.error(f'Error refreshing credentials: {exception!s}')
  else:
    # No credentials file, acquire new credentials from secrets file.
    log.info('Could not find existing credentials. Requesting new tokens.')
    try:
      appflow = flow.InstalledAppFlow.from_client_secrets_file(
          client_secrets_path, scopes)
    except FileNotFoundError as exception:
      log.error(f'Client secrets file not found: {exception!s}')
      sys.exit(1)

    log.info(
        'Starting local HTTP server on localhost:8888 for OAUTH flow. '
        'If running turbinia-client remotely over SSH you will need to tunnel '
        'port 8888.')
    appflow.run_local_server(host='localhost', port=8888, open_browser=False)
    credentials = appflow.credentials

    # Save credentials
    with open(credentials_path, 'w', encoding='utf-8') as token:
      token.write(credentials.to_json())

  return credentials.id_token
