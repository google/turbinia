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
"""Turbinia API - Authentication"""

from functools import wraps

import os
import logging
import json
import jwt
import requests
import google_auth_oauthlib.flow

from fastapi import HTTPException
from fastapi import APIRouter
from fastapi.requests import Request
from fastapi.responses import RedirectResponse, JSONResponse
from turbinia import config

log = logging.getLogger('turbinia:api_server')

auth_router = APIRouter(tags=['Turbinia Authentication'])

# TODO: Remove this line before merging.
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

_config = config.LoadConfig()


def _get_keys(url):
  """Gets identity provider public keys."""
  if isinstance(url, str) and url.startswith("https://"):
    request = requests.get(url)
    return request.json()


async def validate_session(request: Request):
  """Validates that the request is for a valid session."""
  session = request.session
  valid_session = False
  if session:
    if session.get('id_token'):
      log.debug('Got session {}'.format(session.get('id_token')))
      session_token = session.get('id_token')
      return await validate_token(session_token)
  log.debug('No session found.')
  return valid_session


async def validate_token(jwt_token: str):
  """Validates JWT bearer token in Authorization header."""
  keys = _get_keys(_config.OIDC_KEYS).get('keys')
  token_is_valid = False
  if not jwt_token:
    log.debug('invalid token')
    return token_is_valid

  try:
    jwt_header = jwt.get_unverified_header(jwt_token)
    if jwt_header:
      if jwt_header.get('typ') != 'JWT':
        log.debug("Not a JWT token")
        return token_is_valid
      kid = jwt_header.get('kid')
      for key in keys:
        if key.get('kid') == kid:
          idp_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
    jwt_decoded = jwt.decode(
        jwt=jwt_token, key=idp_key, issuer=_config.OIDC_ISSUER,
        audience=_config.OIDC_VALID_CLIENT_IDS, algorithms=['RS256'])
    log.debug('Got valid token: {}'.format(jwt_decoded))
    token_is_valid = True

  except (jwt.DecodeError, jwt.ExpiredSignatureError,
          jwt.ImmatureSignatureError, jwt.InvalidAlgorithmError,
          jwt.InvalidAudience) as exception:
    log.debug("Error decoding token {}".format(exception))

  return token_is_valid


async def validate_auth_header(request: Request):
  """Validates request authorization header."""
  valid_header = False
  for header in request.headers.keys():
    if header.lower() == 'authorization':
      log.debug("Found authorization header")
      header_value = request.headers.get(header)
      if header_value.startswith('Bearer'):
        bearer_token = header_value.split(' ')[1]
        valid_header = await validate_token(bearer_token)
  return valid_header


async def validate_auth(request: Request):
  """Validates whether the request has a valid session or
      a valid Authorization header.

    Args:
      request (Request): Client request.

    Returns: True if API_AUTHENTICATION_ENABLED is False or
      if the request contains a valid jwt token in a session
      cookie or authorization header. Returns False otherwise.
  """
  if not _config.API_AUTHENTICATION_ENABLED:
    return True
  return bool(
      await validate_session(request) or await validate_auth_header(request))


def auth_required(func):
  """Decorator to check for authentication."""

  @wraps(func)
  async def wrapper(*args, **kwargs):
    request = kwargs.get('request')
    is_authenticated = False
    if request:
      is_authenticated = await validate_auth(request)
      if is_authenticated:
        return await func(*args, **kwargs)
    raise HTTPException(status_code=401, detail='Unauthorized')

  return wrapper


@auth_router.route('/logout')
async def logout(request: Request):
  """Deletes an existing session and revoke ID_TOKEN."""
  id_token = request.session.get('id_token')
  if not id_token:
    return JSONResponse(content={'detail': 'Not logged in.'}, status_code=200)

  revoke = requests.post(
      'https://oauth2.googleapis.com/revoke', params={
          'token': request.session.get('access_token')
      }, headers={'content-type': 'application/x-www-form-urlencoded'})
  del request.session['access_token']
  del request.session['id_token']

  if revoke.status_code == 200:
    return JSONResponse(
        content={'detail': 'Session logout successful and ID_TOKEN revoked.'},
        status_code=200)
  return JSONResponse(
      content={
          'detail': 'Session logout successful, ID_TOKEN was not revoked.'
      }, status_code=200)


@auth_router.route('/login')
async def authorize(request: Request):
  """Redirects an unauthenticated client to Google's OAuth2 server."""
  if await validate_auth(request):
    return RedirectResponse(request.url_for('/web'))

  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      _config.WEBUI_CLIENT_SECRETS_FILE, scopes=_config.OIDC_SCOPE)
  flow.redirect_uri = request.url_for('oauth2_callback')

  authorization_url, state = flow.authorization_url(
      access_type='online', include_granted_scopes='true')
  #request.session['state'] = state
  response = RedirectResponse(authorization_url)
  response.set_cookie('state', state, httponly=True, max_age=30)
  return response


@auth_router.route('/oauth2/callback')
async def oauth2_callback(request: Request):
  """Fetches access token and save id_token."""
  state = request.cookies.pop('state')

  #note: the line below fails if session cookie has same_site='strict'
  #state = request.session.get('state')
  if not state:
    raise HTTPException(
        status_code=401, detail='OAuth2 state not found in request.')
  flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
      _config.WEBUI_CLIENT_SECRETS_FILE, scopes=_config.OIDC_SCOPE, state=state,
      autogenerate_code_verifier=True)
  flow.redirect_uri = request.url_for('oauth2_callback')

  authorization_response = str(request.url)
  flow.fetch_token(authorization_response=authorization_response)

  credentials = flow.credentials
  request.session['id_token'] = credentials.id_token
  request.session['access_token'] = credentials.token
  return RedirectResponse('/web')
