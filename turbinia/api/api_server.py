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
import uvicorn
import yaml

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRoute
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles

from turbinia import config
from turbinia.api.routes.router import router

log = logging.getLogger('turbinia:api_server')


def get_application():
  """Returns a FastAPI application object."""
  description = '''This is Turbinia's API server description.'''
  _app = FastAPI(
      title='Turbinia API Server', description=description, version='1.0.0',
      license_info={
          'name': 'Apache License 2.0',
          'url': 'https://www.apache.org/licenses/LICENSE-2.0.html'
      }, routes=router.routes)
  return _app


def set_operation_ids(app: FastAPI):
  """Simplify operation IDs so that generated API clients have
    simpler function names.
    Should be called only after all routes have been added.
    """
  for route in app.routes:
    if isinstance(route, APIRoute):
      route.operation_id = route.name


app = get_application()
origins = ["http://localhost:8080", "http://localhost"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
set_operation_ids(app)


# app.mount("/js", StaticFiles(directory="../../web/dist/js"), name="/js")
# app.mount("/css", StaticFiles(directory="../../web/dist/css"), name="/css")

class TurbiniaAPIServer:
  """Turbinia API server."""

  def __init__(self, app=None, router=None):
    self.app = app if app else get_application()
    self.router = router
    self.openapi_spec = self.app.openapi()
    #self.set_operation_ids()

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


@app.get('/docs/openapi.yaml', include_in_schema=False)
def read_openapi_yaml():
  """Serve the OpenAPI spec in YAML format."""
  openapi_json = app.openapi()
  yaml_s = io.StringIO()
  yaml.dump(openapi_json, yaml_s)
  return Response(yaml_s.getvalue(), media_type='text/yaml')


if __name__ == '__main__':
  api_server = TurbiniaAPIServer(app=app, router=router)
  api_server.start('api_server:app')
