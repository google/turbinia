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
"""Turbinia API client / management tool."""

import logging
import os
import sys

from google_auth_oauthlib import flow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google.auth import exceptions as google_exceptions

_LOGGER_FORMAT = '%(asctime)s %(levelname)s %(name)s - %(message)s'
logging.basicConfig(format=_LOGGER_FORMAT)
log = logging.getLogger('turbiniamgmt:helpers:auth')
log.setLevel(logging.INFO)


def get_oauth2_credentials():
  """Authenticates the user using Google OAuth services."""
  scopes = ['openid', 'https://www.googleapis.com/auth/userinfo.email']
  _CREDENTIALS_FILENAME = '.credentials.json'
  _CLIENT_SECRETS_FILENAME = '.client_secrets.json'

  credentials = None

  # Load credentials file if it exists
  if os.path.exists(_CREDENTIALS_FILENAME):
    try:
      credentials = Credentials.from_authorized_user_file(
          _CREDENTIALS_FILENAME, scopes)
    except ValueError as exception:
      log.error('Error loading credentials: %s', exception)
    # Refresh credentials using existing refresh_token or obtain a new token
    if credentials:
      log.debug(
          'Could not find a valid OAuth2 id_token, checking refresh token.')
      if credentials.refresh_token:
        log.debug('Found a refresh token. Requesting new id_token...')
        try:
          credentials.refresh(Request())
        except google_exceptions.RefreshError as exception:
          log.error('Error refreshing credentials: %s', exception)
  else:
    # No refresh token, obtain new credentials via OAuth2 flow
    log.info('Could not find existing credentials. Requesting new tokens.')
    try:
      appflow = flow.InstalledAppFlow.from_client_secrets_file(
          _CLIENT_SECRETS_FILENAME, scopes)
    except FileNotFoundError as exception:
      log.error('Client secrets file not found: %s', exception)
      sys.exit(1)

    log.info(
        'Starting local HTTP server on localhost:8888 for OAUTH flow. '
        'If running turbiniamgmt remotely over SSH you will need to tunnel '
        'port 8888.')
    appflow.run_local_server(host="localhost", port=8888)
    credentials = appflow.credentials
    # Save credentials
    with open(_CREDENTIALS_FILENAME, 'w', encoding='utf-8') as token:
      token.write(credentials.to_json())

  return credentials.id_token
