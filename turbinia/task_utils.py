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
"""Task runner for Turbinia."""

import datetime
import os
import filelock

import turbinia
from turbinia import config
from turbinia import TurbiniaException
from turbinia.workers.artifact import FileArtifactExtractionTask
from turbinia.workers.analysis.wordpress_access import WordpressAccessLogAnalysisTask
from turbinia.workers.analysis.wordpress_creds import WordpressCredsAnalysisTask
from turbinia.workers.analysis.jenkins import JenkinsAnalysisTask
from turbinia.workers.analysis.jupyter import JupyterAnalysisTask
from turbinia.workers.analysis.linux_acct import LinuxAccountAnalysisTask
from turbinia.workers.analysis.loki import LokiAnalysisTask
from turbinia.workers.analysis.windows_acct import WindowsAccountAnalysisTask
from turbinia.workers.finalize_request import FinalizeRequestTask
from turbinia.workers.cron import CronAnalysisTask
from turbinia.workers.docker import DockerContainersEnumerationTask
from turbinia.workers.grep import GrepTask
from turbinia.workers.fsstat import FsstatTask
from turbinia.workers.hadoop import HadoopAnalysisTask
from turbinia.workers.hindsight import HindsightTask
from turbinia.workers.partitions import PartitionEnumerationTask
from turbinia.workers.plaso import PlasoTask
from turbinia.workers.psort import PsortTask
from turbinia.workers.redis import RedisAnalysisTask
from turbinia.workers.sshd import SSHDAnalysisTask
from turbinia.workers.strings import StringsAsciiTask
from turbinia.workers.strings import StringsUnicodeTask
from turbinia.workers.tomcat import TomcatAnalysisTask
from turbinia.workers.volatility import VolatilityTask
from turbinia.workers.worker_stat import StatTask
from turbinia.workers.binary_extractor import BinaryExtractorTask
from turbinia.workers.bulk_extractor import BulkExtractorTask
from turbinia.workers.photorec import PhotorecTask
from turbinia.workers.abort import AbortTask

config.LoadConfig()

# TODO(aarontp): Remove this map after
# https://github.com/google/turbinia/issues/278 is fixed.
TASK_MAP = {
    'fileartifactextractiontask': FileArtifactExtractionTask,
    'wordpressaccessloganalysistask': WordpressAccessLogAnalysisTask,
    'WordpressCredsAnalysisTask': WordpressCredsAnalysisTask,
    'finalizerequesttask': FinalizeRequestTask,
    'jenkinsanalysistask': JenkinsAnalysisTask,
    'JupyterAnalysisTask': JupyterAnalysisTask,
    'greptask': GrepTask,
    'fsstattask': FsstatTask,
    'hadoopanalysistask': HadoopAnalysisTask,
    'hindsighttask': HindsightTask,
    'LinuxAccountAnalysisTask': LinuxAccountAnalysisTask,
    'WindowsAccountAnalysisTask': WindowsAccountAnalysisTask,
    'LokiAnalysisTask': LokiAnalysisTask,
    'partitionenumerationtask': PartitionEnumerationTask,
    'plasotask': PlasoTask,
    'psorttask': PsortTask,
    'redisanalysistask': RedisAnalysisTask,
    'sshdanalysistask': SSHDAnalysisTask,
    'stringsasciitask': StringsAsciiTask,
    'stringsunicodetask': StringsUnicodeTask,
    'tomcatanalysistask': TomcatAnalysisTask,
    'volatilitytask': VolatilityTask,
    'stattask': StatTask,
    'binaryextractortask': BinaryExtractorTask,
    'bulkextractortask': BulkExtractorTask,
    'dockercontainersenumerationtask': DockerContainersEnumerationTask,
    'photorectask': PhotorecTask,
    'aborttask': AbortTask,
    'crontask': CronAnalysisTask
}


def task_deserialize(input_dict):
  """Converts an input dictionary back into a TurbiniaTask object.

  Args:
    input_dict (dict): TurbiniaTask object dictionary.

  Returns:
    TurbiniaTask: Deserialized object.
  """

  type_ = input_dict['name']
  try:
    task = getattr(sys.modules['turbinia.task_utils'], type_)()
  except AttributeError:
    message = (
        "Could not import {0:s} object! Make sure it is imported where "
        "this method is defined.".format(type_))
    log.error(message)
    raise TurbiniaException(message)
  task.__dict__.update(input_dict)
  # Pretty sure this is not needed? Testing DONOTSUBMIT
  # task.output_manager = output_manager.OutputManager()
  task.output_manager.__dict__.update(input_dict['output_manager'])
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
  if os.path.exists(config.SCALEDOWN_WORKER_FILE):
    raise psq.Retry()

  # try to acquire lock and timeout and requeue task if it's in use
  try:
    lock = filelock.FileLock(config.LOCK_FILE)
    with lock.acquire(timeout=0.001):
      obj = task_deserialize(obj)
      run = obj.run_wrapper(*args, **kwargs)
  except filelock.Timeout:
    raise psq.Retry()

  return run
