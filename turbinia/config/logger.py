# -*- coding: utf-8 -*-
# Copyright 2017 Google Inc.
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
"""Sets up logging."""

import logging
import logging.handlers
import warnings
import os
import sys

from turbinia import config
from turbinia import TurbiniaException

# Environment variable to look for node name in
ENVNODENAME = 'NODE_NAME'


def setup(need_file_handler=True, need_stream_handler=True, log_file_path=None):
  """Set up logging parameters.

  This will also set the root logger, which is the default logger when a named
  logger is not specified.  We currently use 'turbinia' as the named logger,
  however some external modules that are called by Turbinia can use the root
  logger, so we want to be able to optionally configure that as well.
  """
  # Remove known warning about credentials
  warnings.filterwarnings(
      'ignore', 'Your application has authenticated using end user credentials')

  logger = logging.getLogger('turbinia')
  uvicorn_error = logging.getLogger('uvicorn.error')
  uvicorn_access = logging.getLogger('uvicorn.access')
  # Eliminate double logging from root logger
  logger.propagate = False
  uvicorn_error.propagate = False
  uvicorn_access.propagate = False
  # We only need a handler if one of that type doesn't exist already
  if logger.handlers:
    for handler in logger.handlers:
      # Want to do strict type-checking here because is instance will include
      # subclasses and so won't distinguish between StreamHandlers and
      # FileHandlers.
      # pylint: disable=unidiomatic-typecheck
      if type(handler) == logging.FileHandler:
        need_file_handler = False

      # pylint: disable=unidiomatic-typecheck
      if type(handler) == logging.StreamHandler:
        need_stream_handler = False

  if need_file_handler:
    try:
      config.LoadConfig()
    except TurbiniaException as exception:
      print(
          f'Could not load config file ({exception!s}).\n{config.CONFIG_MSG:s}')
      sys.exit(1)

    # Check if a user specified log path was provided else create default path
    if not log_file_path:
      # Create LOG directory if it doesn't exist
      if not os.path.exists(config.LOG_DIR):
        os.mkdir(config.LOG_DIR)
      log_name = os.uname().nodename
      # Check if NODE_NAME available for GKE setups
      if ENVNODENAME in os.environ:
        log_name = log_name + f'.{os.environ[ENVNODENAME]!s}'
      log_file_path = os.path.join(config.LOG_DIR, log_name) + '.log'

    file_handler = logging.FileHandler(log_file_path)
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s | %(message)s')
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    uvicorn_error.addHandler(file_handler)
    uvicorn_access.addHandler(file_handler)

  console_handler = logging.StreamHandler(sys.stdout)
  formatter = logging.Formatter(
      '%(asctime)s [%(levelname)s] %(name)s | %(message)s', '%Y-%m-%d %H:%M:%S')
  console_handler.setFormatter(formatter)
  if need_stream_handler:
    logger.addHandler(console_handler)
    uvicorn_error.addHandler(console_handler)
    uvicorn_access.addHandler(console_handler)
  # Configure the root logger to use exactly our handlers because other modules
  # like PSQ use this, and we want to see log messages from it when executing
  # from CLI.
  root_log = logging.getLogger()
  for handler in root_log.handlers:
    root_log.removeHandler(handler)
  root_log.addHandler(console_handler)

  if need_file_handler:
    root_log.addHandler(file_handler)

  # Set filelock logging to ERROR due to log spam
  logging.getLogger('filelock').setLevel(logging.ERROR)
