# -*- coding: utf-8 -*-
# Copyright 2021 Google Inc.
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
"""Server objects for Turbinia."""

import logging

from prometheus_client import start_http_server
from turbinia import config
from turbinia.config import logger
from turbinia import task_manager

config.LoadConfig()
log = logging.getLogger('turbinia')


def setup(is_client=False):
  config.LoadConfig()
  if is_client:
    logger.setup(need_file_handler=False)
  else:
    logger.setup()


class TurbiniaServer:
  """Turbinia Server class.

  Attributes:
    task_manager (TaskManager): An object to manage turbinia tasks.
  """

  def __init__(self, jobs_denylist=None, jobs_allowlist=None):
    """Initializes Turbinia Server.

    Args:
      jobs_denylist (Optional[list[str]]): Jobs we will exclude from running
      jobs_allowlist (Optional[list[str]]): The only Jobs we will include to run
    """
    setup()
    self.task_manager = task_manager.get_task_manager()
    self.task_manager.setup(jobs_denylist, jobs_allowlist)

  def start(self):
    """Start Turbinia Server."""
    if config.PROMETHEUS_ENABLED:
      if config.PROMETHEUS_PORT and config.PROMETHEUS_ADDR:
        log.info('Starting Prometheus endpoint.')
        start_http_server(
            port=config.PROMETHEUS_PORT, addr=config.PROMETHEUS_ADDR)
      else:
        log.info('Prometheus enabled but port or address not set!')
    log.info('Running Turbinia Server.')
    self.task_manager.run()

  def add_evidence(self, evidence_):
    """Add evidence to be processed."""
    self.task_manager.add_evidence(evidence_)
