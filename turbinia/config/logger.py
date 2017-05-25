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

from turbinia import config

def setup(root=False):
  """Set up logging parameters.

  By default this will not set the root logger, which is the default logger when
  a named logger is not specified.  We currently use 'turbinia' as the named
  logger, however some external modules that are called by Turbinia can use the
  root logger, so we want to be able to optionally configure that as well.

  Args:
    root: Boolean indicating whether root logger should also be configured.
  """
  # TODO(aarontp): Add a config option to set the log level
  config.LoadConfig()
  log = logging.getLogger('turbinia')

  file_handler = logging.FileHandler(config.LOG_FILE)
  formatter = logging.Formatter(u'%(asctime)s:%(levelname)s:%(message)s')
  file_handler.setFormatter(formatter)
  file_handler.setLevel(logging.DEBUG)

  console_handler = logging.StreamHandler()
  formatter = logging.Formatter(u'[%(levelname)s] %(message)s')
  console_handler.setFormatter(formatter)

  log.addHandler(file_handler)
  log.addHandler(console_handler)

  # Optionally configure the root logger because other modules like PSQ use
  # this, and we want to see log messages from it when executing from CLI.
  if root:
    root_log = logging.getLogger()
    root_log.addHandler(console_handler)
    root_log.setLevel(logging.DEBUG)
