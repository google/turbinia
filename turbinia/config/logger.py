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

from __future__ import unicode_literals
import logging

import warnings
import logging.handlers
from turbinia import config
from turbinia import TurbiniaException


def setup(need_file_handler=True, need_stream_handler=True):
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
  # Eliminate double logging from root logger
  logger.propagate = False

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
          'Could not load config file ({0!s}).\n{1:s}'.format(
              exception, config.CONFIG_MSG))
      sys.exit(1)

    file_handler = logging.FileHandler(config.LOG_FILE)
    formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(message)s')
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)

  console_handler = logging.StreamHandler()
  formatter = logging.Formatter('[%(levelname)s] %(message)s')
  console_handler.setFormatter(formatter)
  if need_stream_handler:
    logger.addHandler(console_handler)

  # Configure the root logger to use exactly our handlers because other modules
  # like PSQ use this, and we want to see log messages from it when executing
  # from CLI.
  root_log = logging.getLogger()
  for handler in root_log.handlers:
    root_log.removeHandler(handler)
  root_log.addHandler(console_handler)
  if need_file_handler:
    root_log.addHandler(file_handler)
