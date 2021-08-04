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
"""Task used to abort a job"""

import psq
from celery import states as celery_states
from turbinia import config
from turbinia.workers import TurbiniaTask


class AbortTask(TurbiniaTask):
  """Task producing a graceful job termination result."""

  task_config = {'reason': 'Recipe provided is invalid'}

  def create_stub(self):
    """Creates a mock task stub"""
    if config.TASK_MANAGER.lower() == 'psq':
      self.stub = MockPSQStub()
    elif config.TASK_MANAGER.lower() == 'celery':
      self.stub = MockCeleryStub()

  def run(self, evidence, result):
    """Produce a verbose result to halp troubleshoot issues.
    Args:
        evidence (Evidence object):  The evidence we will process.
        result (TurbiniaTaskResult): The object to place task results into.

    Returns:
        TurbiniaTaskResult object.
    """
    result.close(self, True, '{0:s}'.format(self.task_config['reason']))
    return result


class MockPSQStub:
  """Mock PSQ task stub"""

  def __init__(self):
    self.status = psq.task.FINISHED

  def get_task(self):
    """Returns this mock task stub (self).
    
    Returns:
        MockPSQStub: The current instantiated object
    """
    return self


class MockCeleryStub:
  """Mock Celery task stub"""

  def __init__(self):
    self.status = celery_states.SUCCESS
