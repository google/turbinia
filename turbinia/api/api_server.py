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
from os import getenv
import yaml
import uvicorn

from fastapi import FastAPI
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.routing import APIRoute

from turbinia import config
from turbinia.config import logger
from turbinia.api.routes.router import api_router
from turbinia.api.routes.ui import ui_router

logger.setup(need_file_handler=True, need_stream_handler=True)
log = logging.getLogger('turbinia')
log.setLevel(logging.INFO)


def get_application() -> FastAPI:
  """Returns a FastAPI application object."""
  description: str = (
      'Turbinia is an open-source framework for deploying,'
      ' managing, and running distributed forensic workloads')
  fastapi_app = FastAPI(
      title='Turbinia API Server', description=description, version='1.0.0',
      license_info={
          'name': 'Apache License 2.0',
          'url': 'https://www.apache.org/licenses/LICENSE-2.0.html'
      })
  return fastapi_app


def set_operation_ids(app: FastAPI) -> None:
  """Simplify operation ID names to be used by client generator.

 This method must only be called after all routes have been initialized.
  """
  for route in app.routes:
    if isinstance(route, APIRoute):
      route.operation_id = route.name


app = get_application()

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.API_ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=['GET', 'POST'],
    allow_headers=['*'],
)

app.include_router(api_router)
app.include_router(ui_router)

set_operation_ids(app)


@app.get(
    '/openapi.yaml', tags=['OpenAPI Specification'], include_in_schema=False)
def read_openapi_yaml():
  """Serve the OpenAPI specification in YAML format."""
  openapi_json = app.openapi()
  yaml_s = io.StringIO()
  yaml.dump(openapi_json, yaml_s)
  return Response(yaml_s.getvalue(), media_type='text/yaml')


class TurbiniaAPIServer:
  """Turbinia API server."""

  def __init__(self, app=None):
    self.app: FastAPI = app if app else get_application()

  def start(self, app_name: str):
    """Runs the Turbinia API server

    Args:
      app_name (str): module:app string used by Uvicorn
          to start the HTTP server.
    """
    reload = False
    workers = 4
    log_level = 'info'
    if getenv('TURBINIA_DEBUG') == '1':
      reload = True
      workers = 0
      log_level = 'debug'

    uvicorn.run(
        app_name, host=config.API_SERVER_ADDRESS, port=config.API_SERVER_PORT,
        log_config=None, log_level=log_level, reload=reload, workers=workers)


if __name__ == '__main__':
  api_server = TurbiniaAPIServer(app=app)
  api_server.start('api_server:app')
