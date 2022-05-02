#-*- coding: utf-8 -*-
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
"""Task utilities for Turbinia."""

from datetime import datetime
import logging
import os
import sys

import filelock

import turbinia
from turbinia import config
from turbinia.config import DATETIME_FORMAT
from turbinia import TurbiniaException

log = logging.getLogger('turbinia')

config.LoadConfig()


class TaskLoader():
  """Utility class for handling Task loading/checking/deserialization.

  Attributes:
    TASK_LIST(list): A list of all valid Tasks.
  """

  TASK_LIST = [
      'AbortTask',
      'BinaryExtractorTask',
      'BulkExtractorTask',
      'CronAnalysisTask',
      'DfdeweyTask',
      'DockerContainersEnumerationTask',
      'FileArtifactExtractionTask',
      'FileSystemTimelineTask',
      'FinalizeRequestTask',
      'FsstatTask',
      'GitlabTask',
      'GrepTask',
      'HadoopAnalysisTask',
      'HindsightTask',
      'JenkinsAnalysisTask',
      'JupyterAnalysisTask',
      'LinuxAccountAnalysisTask',
      'LokiAnalysisTask',
      'PartitionEnumerationTask',
      'PhotorecTask',
      'PlasoTask',
      'PsortTask',
      'RedisAnalysisTask',
      'SSHDAnalysisTask',
      'StatTask',
      'StringsAsciiTask',
      'StringsUnicodeTask',
      'TomcatAnalysisTask',
      'VolatilityTask',
      'WindowsAccountAnalysisTask',
      'WordpressAccessLogAnalysisTask',
      'WordpressCredsAnalysisTask',
  ]

  def check_task_name(self, task_name):
    """Checks whether a given task name is a valid task

    Args:
      task_name(str): Name of the Task to check.

    Returns:
      bool: True if task with the given name exists, else False
    """
    for task in self.TASK_LIST:
      if task.lower() == task_name.lower():
        return True
    return False

  def get_task(self, task_name):
    """Gets an instantiated Task object for the given name.

    Args:
      task_name(str): Name of the Task to return.

    Returns:
      TurbiniaTask: An instantiated Task object.
    """
    # TODO(aarontp): Remove this list after
    # https://github.com/google/turbinia/issues/278 is fixed.
    #
    # Late imports to minimize what loads all Tasks
    from turbinia.workers.abort import AbortTask
    from turbinia.workers.analysis.jenkins import JenkinsAnalysisTask
    from turbinia.workers.analysis.jupyter import JupyterAnalysisTask
    from turbinia.workers.analysis.linux_acct import LinuxAccountAnalysisTask
    from turbinia.workers.analysis.loki import LokiAnalysisTask
    from turbinia.workers.analysis.windows_acct import WindowsAccountAnalysisTask
    from turbinia.workers.analysis.wordpress_access import WordpressAccessLogAnalysisTask
    from turbinia.workers.analysis.wordpress_creds import WordpressCredsAnalysisTask
    from turbinia.workers.artifact import FileArtifactExtractionTask
    from turbinia.workers.binary_extractor import BinaryExtractorTask
    from turbinia.workers.bulk_extractor import BulkExtractorTask
    from turbinia.workers.cron import CronAnalysisTask
    from turbinia.workers.dfdewey import DfdeweyTask
    from turbinia.workers.docker import DockerContainersEnumerationTask
    from turbinia.workers.file_system_timeline import FileSystemTimelineTask
    from turbinia.workers.finalize_request import FinalizeRequestTask
    from turbinia.workers.fsstat import FsstatTask
    from turbinia.workers.gitlab import GitlabTask
    from turbinia.workers.grep import GrepTask
    from turbinia.workers.hadoop import HadoopAnalysisTask
    from turbinia.workers.hindsight import HindsightTask
    from turbinia.workers.partitions import PartitionEnumerationTask
    from turbinia.workers.photorec import PhotorecTask
    from turbinia.workers.plaso import PlasoTask
    from turbinia.workers.psort import PsortTask
    from turbinia.workers.redis import RedisAnalysisTask
    from turbinia.workers.sshd import SSHDAnalysisTask
    from turbinia.workers.strings import StringsAsciiTask
    from turbinia.workers.strings import StringsUnicodeTask
    from turbinia.workers.tomcat import TomcatAnalysisTask
    from turbinia.workers.volatility import VolatilityTask
    from turbinia.workers.worker_stat import StatTask

    for task in self.TASK_LIST:
      if task.lower() == task_name.lower():
        try:
          task_obj = locals()[task]
          return task_obj()
        except (AttributeError, KeyError):
          message = (
              "Could not import {0:s} object! Make sure it is imported where "
              "this method is defined.".format(task_name))
          log.error(message)
          raise TurbiniaException(message)

    return

  def get_task_names(self):
    """Returns a list of Task names.

    Returns:
      (list) All Task names.
    """
    return self.TASK_LIST


def task_deserialize(input_dict):
  """Converts an input dictionary back into a TurbiniaTask object.

  Args:
    input_dict (dict): TurbiniaTask object dictionary.

  Returns:
    TurbiniaTask: Deserialized object.
  """

  type_ = input_dict['name']
  task_loader = TaskLoader()
  task = task_loader.get_task(type_)
  if not task:
    raise TurbiniaException('Could not load Task module {0:s}'.format(type_))
  # Remove serialized output manager because this gets reinstantiated when the
  # empty Task is instantiated and we don't want to overwrite it.
  input_dict.pop('output_manager')
  task.__dict__.update(input_dict)
  task.start_time = datetime.strptime(input_dict['start_time'], DATETIME_FORMAT)
  task.last_update = datetime.strptime(
      input_dict['last_update'], DATETIME_FORMAT)
  return task


def task_runner(obj, *args, **kwargs):
  """Wrapper function to run specified TurbiniaTask object.

  Args:
    obj: An instantiated TurbiniaTask object.
    *args: Any Args to pass to obj.
    **kwargs: Any keyword args to pass to obj.

  Returns:
    Output from TurbiniaTask (should be TurbiniaTaskResult).
  """

  # GKE Specific - do not queue more work if pod places this file
  if config.TASK_MANAGER.lower() == 'psq':
    if os.path.exists(config.SCALEDOWN_WORKER_FILE):
      # Late import because this is only needed for PSQ
      import psq
      raise psq.Retry()

  # Try to acquire lock, timeout and requeue task if the worker
  # is already processing a task.
  try:
    lock = filelock.FileLock(config.LOCK_FILE)
    with lock.acquire(timeout=0.001):
      obj = task_deserialize(obj)
      run = obj.run_wrapper(*args, **kwargs)
  except filelock.Timeout:
    if config.TASK_MANAGER.lower() == 'psq':
      # Late import because this is only needed for PSQ
      import psq
      raise psq.Retry()
  # *Always* make sure we release the lock
  finally:
    lock.release()

  return run
