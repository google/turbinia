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
"""Turbinia API server."""

import io
import logging
import pathlib
import uvicorn
import yaml

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRoute
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles

from starlette_oauth2_api import AuthenticateMiddleware

from turbinia import config
from turbinia.api.routes.router import router

log = logging.getLogger('turbinia:api_server')


def get_application():
  """Returns a FastAPI application object."""
  description = '''Turbinia API server'''
  _app = FastAPI(
      title='Turbinia API Server', description=description, version='1.0.0',
      license_info={
          'name': 'Apache License 2.0',
          'url': 'https://www.apache.org/licenses/LICENSE-2.0.html'
      }, routes=router.routes)
  return _app


def set_operation_ids(app: FastAPI):
  """Simplify operation ID names to be used by client generator.

 This method must only be called after all routes have been initialized.
  """
  for route in app.routes:
    if isinstance(route, APIRoute):
      route.operation_id = route.name


def serve_static_content(app: FastAPI):
  """Configure the application to serve static content.

  This method must be called after all routes have been initialized.
  """
  this_path = pathlib.Path(__file__).parent.resolve()
  web_content_path = this_path.parent.parent.joinpath('web/dist')
  css_content_path = web_content_path.joinpath('css')
  js_content_path = web_content_path.joinpath('js')
  if web_content_path.exists():
    try:
      app.mount(
          "/web", StaticFiles(directory=web_content_path, html=True), name="/")
      app.mount("/css", StaticFiles(directory=css_content_path), name="/css")
      app.mount("/js", StaticFiles(directory=js_content_path), name="/js")
    except RuntimeError as exception:
      log.error(
          'Unable to serve Web UI static content: {0!s}'.format(exception))
  else:
    log.info(
        'Web UI path {0!s} could not be found. Will not serve Web UI.'.format(
            web_content_path))


def configure_authentication_providers(app: FastAPI):
  """Configure the application's authentication providers.

  Example provider configuration using starlette-oauth2-pai:
  """
  app.add_middleware(
      AuthenticateMiddleware,
      providers={
          'web-ui': {
              'keys': 'https://www.googleapis.com/oauth2/v3/certs',
              'issuer': 'https://accounts.google.com',
              'audience': 'GOOGLE_WEB_CLIENT_ID',
          },
          'cli-client': {
              'keys': 'https://www.googleapis.com/oauth2/v3/certs',
              'issuer': 'https://accounts.google.com',
              'audience': 'GOOGLE_NATIVE_CLIENT_ID',
          }
      },
      public_paths={'/'},
  )


app = get_application()

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.API_ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

if config.API_AUTHENTICATION_ENABLED:
  configure_authentication_providers(app)

set_operation_ids(app)
serve_static_content(app)


class TurbiniaAPIServer:
  """Turbinia API server."""

  def __init__(self, app=None, router=None):
    self.app = app if app else get_application()
    self.router = router
    self.openapi_spec = self.app.openapi()

  def start(self, app_name: str):
    """Runs the Turbinia API server

    Args:
      app_name (str): module:app string used by Uvicorn
          to start the HTTP server.
    """
    _config = config.LoadConfig()
    uvicorn.run(
        app_name, host=_config.API_SERVER_ADDRESS, port=_config.API_SERVER_PORT,
        log_level="info", reload=True)


@app.get('/docs/openapi.yaml', tags=['OpenAPI Specification'])
def read_openapi_yaml():
  """Serve the OpenAPI specification in YAML format."""
  openapi_json = app.openapi()
  yaml_s = io.StringIO()
  yaml.dump(openapi_json, yaml_s)
  return Response(yaml_s.getvalue(), media_type='text/yaml')


if __name__ == '__main__':
  api_server = TurbiniaAPIServer(app=app, router=router)
  api_server.start('api_server:app')
