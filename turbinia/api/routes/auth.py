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
from oauthlib.oauth2.rfc6749 import errors as oauthlib_errors
from google_auth_oauthlib import flow as oauthlib_flow
from fastapi import HTTPException
from fastapi import APIRouter
from fastapi.requests import Request
from fastapi.responses import RedirectResponse, JSONResponse
from turbinia import config

log = logging.getLogger('turbinia:api_server')
log.setLevel(logging.DEBUG)

auth_router = APIRouter(tags=['Turbinia Authentication'])

# TODO: Remove this line before merging.
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

_config = config.LoadConfig()

_PUBLIC_KEY_CACHE = {}


def update_key_cache():
  """Updates the application's public key cache.

  This method ensures we do not query the identity provider's
  endpoint every time a token's signature must be validated.
  """
  keys = get_oidc_keys()
  for key in keys.get('keys'):
    key_id = key.get('kid')
    if not key_id in _PUBLIC_KEY_CACHE:
      log.debug('Updating public key cache with key id {}'.format(key_id))
      _PUBLIC_KEY_CACHE[key_id] = jwt.algorithms.RSAAlgorithm.from_jwk(
          json.dumps(key))


def get_oidc_keys():
  """Gets identity provider public keys.

  Returns: JSON dictionary of public keys from the identity
      provider.
  """
  keys = None
  url = _config.OIDC_KEYS
  if isinstance(url, str) and url.startswith("https://"):
    request = requests.get(url)
    keys = request.json()
  return keys


update_key_cache()


async def validate_session(request: Request):
  """Validates that the request is for a valid session."""
  session = request.session
  valid_session = False
  if session:
    if session.get('id_token'):
      log.debug('Got session {}'.format(session.get('id_token')))
      session_token = session.get('id_token')
      valid_session = await validate_token(session_token)
  return valid_session


async def validate_auth_header(request: Request):
  """Validates request authorization header."""
  valid_header = False
  for header in request.headers.keys():
    if header.lower() == 'authorization':
      log.debug("Found authorization header")
      header_value = request.headers.get(header)
      if header_value.startswith('Bearer'):
        bearer_token = header_value.split(' ')[1]
        log.debug('Found token: {}'.format(bearer_token))
        valid_header = await validate_token(bearer_token)
  return valid_header


async def validate_token(jwt_token: str):
  """Validates JWT bearer token in Authorization header."""
  if not jwt_token:
    log.debug('invalid token')
    return False
  jwt_decoded = None

  try:
    jwt_header = jwt.get_unverified_header(jwt_token)
    if jwt_header:
      if jwt_header.get('typ') != 'JWT':
        log.debug("Token is not a JWT token.")
        return False
      kid = jwt_header.get('kid')

      # check if public key is cached.
      if not kid in _PUBLIC_KEY_CACHE:
        log.debug('Key {} not found, updateing cache'.format(kid))
        update_key_cache()
        idp_key = _PUBLIC_KEY_CACHE.get(kid)
      else:
        # use cached public key.
        log.debug('Using key from cache: {}'.format(kid))
        idp_key = _PUBLIC_KEY_CACHE.get(kid)

    # The token was signed with an invalid key.
    if not idp_key:
      return False

    jwt_decoded = jwt.decode(
        jwt=jwt_token, key=idp_key, issuer=_config.OIDC_ISSUER,
        audience=_config.OIDC_VALID_CLIENT_IDS, algorithms=['RS256'])
    log.debug('Got valid token: {}'.format(jwt_decoded))

  except (jwt.DecodeError, jwt.ExpiredSignatureError,
          jwt.ImmatureSignatureError, jwt.InvalidAlgorithmError,
          jwt.InvalidAudience) as exception:
    log.debug("Error decoding token {}".format(exception))

  return bool(jwt_decoded)


async def validate_auth(request: Request):
  """Validates whether an incoming request has a valid session or
      a valid Authorization header.

    This method can be invoked via FastAPI's dependency injection
    mechanism (Depends()).

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
  """Decorator to check for valid authentication on API endpoint requests.

  This decorator should only be used for API endpoints because it will return
  HTTP status code 401. In the Web UI we would want to redirect the user to
  the login URI.
  """

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

  flow = oauthlib_flow.Flow.from_client_secrets_file(
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
  if not state:
    raise HTTPException(
        status_code=401, detail='OAuth2 state not found in request.')

  flow = oauthlib_flow.Flow.from_client_secrets_file(
      _config.WEBUI_CLIENT_SECRETS_FILE, scopes=_config.OIDC_SCOPE, state=state,
      autogenerate_code_verifier=True)
  flow.redirect_uri = request.url_for('oauth2_callback')

  authorization_response = str(request.url)
  try:
    flow.fetch_token(authorization_response=authorization_response)
  except oauthlib_errors.InsecureTransportError:
    raise HTTPException(
        status_code=401,
        detail='Unable to complete OAuth2 authentication flow over insecure transport'
    )
  credentials = flow.credentials
  request.session['id_token'] = credentials.id_token
  request.session['access_token'] = credentials.token
  return RedirectResponse('/web')
