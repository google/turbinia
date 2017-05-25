# Copyright 2015 Google Inc.
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
"""Main Turbinia application."""

import logging
import os
import sys

from turbinia import config

log = logging.getLogger('turbinia')

VERSION = '20170501'


class TurbiniaException(Exception):
  pass

try:
  config.LoadConfig()
except config.TurbiniaConfigException as e:
  # pylint: disable=logging-format-interpolation
  log.fatal('Could not load Turbinia config: {0:s}'.format(str(e)))
  sys.exit(1)
