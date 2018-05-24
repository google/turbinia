# -*- coding: utf-8 -*-
# Copyright 2016 Google Inc.
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
"""Task manager for Turbinia."""

from __future__ import unicode_literals

import logging
import time
import traceback

import psq
from google.cloud import datastore
from google.cloud import pubsub
from google.gax.errors import GaxError

from celery import states as celery_states

import turbinia
from turbinia import evidence
from turbinia import config
from turbinia import jobs
from turbinia import pubsub as turbinia_pubsub
from turbinia import state_manager

log = logging.getLogger('turbinia')


def get_task_manager():
  """Return task manager object based on config.

  Returns
    Initialized TaskManager object.
  """
  config.LoadConfig()
  if config.TASK_MANAGER == 'PSQ':
    return PSQTaskManager()
  elif config.TASK_MANAGER == 'Celery':
    return CeleryTaskManager()
  else:
    msg = 'Task Manager type "{0:s}" not implemented'.format(
        config.TASK_MANAGER)
    raise turbinia.TurbiniaException(msg)


def task_runner(obj, *args, **kwargs):
  """Wrapper function to run specified TurbiniaTask object.

  Args:
    obj: An instantiated TurbiniaTask object.
    *args: Any Args to pass to obj.
    **kwargs: Any keyword args to pass to obj.

  Returns:
    Output from TurbiniaTask (should be TurbiniaTaskResult).
  """
  return obj.run_wrapper(*args, **kwargs)


class BaseTaskManager(object):
  """Class to manage Turbinia Tasks.

  Handles incoming new Evidence messages, adds new Tasks to the queue and
  processes results from Tasks that have run.

  Attributes:
    jobs: A list of instantiated job objects
    evidence: A list of evidence objects to process
    state_manager: State manager object to handle syncing with storage
    tasks: A list of outstanding TurbiniaTask objects
  """

  def __init__(self):
    self.jobs = []
    self.evidence = []
    self.tasks = []
    self.state_manager = state_manager.get_state_manager()

  def _backend_setup(self):
    """Sets up backend dependencies.

    Raises:
      TurbiniaException: When encountering fatal errors setting up dependencies.
    """
    raise NotImplementedError

  def setup(self):
    """Does setup of Task manager and its dependencies."""
    self._backend_setup()
    # TODO(aarontp): Consider instantiating a job per evidence object
    self.jobs = jobs.get_jobs()

  def add_evidence(self, evidence_):
    """Adds new evidence and creates tasks to process it.

    This creates all tasks configured to process the given type of evidence.

    Args:
      evidence_: evidence object to add.

    Raises:
      TurbiniaException: When no Jobs are found.
    """
    if not self.jobs:
      raise turbinia.TurbiniaException(
          'Jobs must be registered before evidence can be added')
    log.info('Adding new evidence: {0:s}'.format(str(evidence_)))
    self.evidence.append(evidence_)
    job_count = 0
    # TODO(aarontp): Add some kind of loop detection in here so that jobs can
    # register for Evidence(), or or other evidence types that may be a super
    # class of the output of the job itself.  Short term we could potentially
    # have a run time check for this upon Job instantiation to prevent it.
    for job in self.jobs:
      # Doing a strict type check here for now until we can get the above
      # comment figured out.
      # pylint: disable=unidiomatic-typecheck
      if [True for t in job.evidence_input if type(evidence_) == t]:
        log.info(
            'Adding {0:s} job to process {1:s}'.format(
                job.name, evidence_.name))
        job_count += 1
        for task in job.create_tasks([evidence_]):
          task.base_output_dir = config.OUTPUT_DIR
          self.add_task(task, evidence_)

    if not job_count:
      log.warning(
          'No Jobs/Tasks were created for Evidence [{0:s}]. '
          'Jobs may need to be configured to allow this type of '
          'Evidence as input'.format(str(evidence_)))

  def check_done(self):
    """Checks to see if we have any outstanding tasks.

    Returns:
      Bool indicating whether we are done.
    """
    return not bool(len(self.tasks))

  def get_evidence(self):
    """Checks for new evidence to process.

    Returns:
      A list of Evidence objects
    """
    raise NotImplementedError

  def add_task(self, task, evidence_):
    """Adds a task and evidence to process to the task manager.

    Args:
      task: An instantiated Turbinia Task
      evidence_: An Evidence object to be processed.
    """
    task.request_id = evidence_.request_id
    self.tasks.append(task)
    self.state_manager.write_new_task(task)
    self.enqueue_task(task, evidence_)

  def remove_task(self, task):
    """Removes a task from the queue; Usually after completion or failure.

    Args:
      task: A TurbiniaTask object
    """
    task.touch()
    self.state_manager.update_task(task)
    self.tasks.remove(task)

  def enqueue_task(self, task, evidence_):
    """Enqueues a task and evidence in the implementation specific task queue.

    Args:
      task: An instantiated Turbinia Task
      evidence_: An Evidence object to be processed.
    """
    raise NotImplementedError

  def finalize_result(self, task_result):
    """Runs final task results recording.

    self.process_tasks handles things that have failed at the task queue layer
    (i.e. PSQ), and this method handles tasks that have potentially failed
    below that layer (i.e. somewhere in our Task code).

    Args:
      task_result: The TurbiniaTaskResult object
    """
    if not task_result.successful:
      log.error('Task {0:s} from {1:s} was not successful'.format(
          task_result.task_name, task_result.worker_name))
    else:
      log.info(
          'Task {0:s} from {1:s} executed with status [{2:s}]'.format(
              task_result.task_name, task_result.worker_name,
              task_result.status))

    if not isinstance(task_result.evidence, list):
      log.info(
          'Task {0:s} from {1:s} did not return evidence list'.format(
              task_result.task_name, task_result.worker_name))
      return

    for evidence_ in task_result.evidence:
      if isinstance(evidence_, evidence.Evidence):
        log.info(
            'Task {0:s} from {1:s} returned Evidence {2:s}'.format(
                task_result.task_name, task_result.worker_name, evidence_.name))
        self.add_evidence(evidence_)
      else:
        log.error(
            'Task {0:s} from {1:s} returned non-Evidence output type '
            '{2:s}'.format(
                task_result.task_name, task_result.worker_name,
                type(task_result.evidence)))

  def process_tasks(self):
    """Process any tasks that need to be processed.

    Returns:
      A list of tasks that have completed.
    """
    raise NotImplementedError

  def run(self):
    """Main run loop for TaskManager."""
    log.info('Starting Task Manager run loop')
    while True:
      # pylint: disable=expression-not-assigned
      [self.add_evidence(x) for x in self.get_evidence()]

      for task in self.process_tasks():
        if task.result:
          self.finalize_result(task.result)
        self.remove_task(task)

      [self.state_manager.update_task(t) for t in self.tasks]
      if config.SINGLE_RUN and self.check_done():
        log.info('No more tasks to process.  Exiting now.')
        return

      # TODO(aarontp): Add config var for this.
      time.sleep(10)


class CeleryTaskManager(BaseTaskManager):
  """Celery implementation of BaseTaskManager.

  Attributes:
    celery (TurbiniaCelery): Celery task queue, handles worker tasks.
    kombu (TurbiniaKombu): Kombu queue, handles receiving evidence.
  """

  def __init__(self):
    self.celery = None
    self.kombu = None
    config.LoadConfig()
    super(CeleryTaskManager, self).__init__()

  def _backend_setup(self):
    self.celery = turbinia_pubsub.TurbiniaCelery()
    self.celery.setup()
    self.kombu = turbinia_pubsub.TurbiniaKombu(config.KOMBU_CHANNEL)
    self.kombu.setup()

  def process_tasks(self):
    """Determine the current state of our tasks.

    Returns:
      list[TurbiniaTask]: all completed tasks
    """
    completed_tasks = []
    for task in self.tasks:
      celery_task = task.stub
      if not celery_task:
        log.debug('Task {0:s} not yet created'.format(task.stub.task_id))
      elif celery_task.status == celery_states.STARTED:
        log.debug('Task {0:s} not finished'.format(celery_task.id))
      elif celery_task.status == celery_states.FAILURE:
        log.warning('Task {0:s} failed.'.format(celery_task.id))
        completed_tasks.append(task)
      elif celery_task.status == celery_states.SUCCESS:
        task.result = celery_task.result
        completed_tasks.append(task)
      else:
        log.debug('Task {0:s} status unknown'.format(celery_task.id))

    outstanding_task_count = len(self.tasks) - len(completed_tasks)
    log.info('{0:d} Tasks still outstanding.'.format(outstanding_task_count))
    # pylint: disable=expression-not-assigned
    return completed_tasks

  def get_evidence(self):
    """Receives new evidence.

    Returns:
      list[Evidence]: evidence to process.
    """
    requests = self.kombu.check_messages()
    evidence_list = []
    for request in requests:
      for evidence_ in request.evidence:
        if not evidence_.request_id:
          evidence_.request_id = request.request_id
        log.info(
            'Received evidence [{0:s}] from Kombu message.'.format(
                str(evidence_)))
        evidence_list.append(evidence_)
    return evidence_list

  def enqueue_task(self, task, evidence_):
    log.info(
        'Adding Celery task {0:s} with evidence {1:s} to queue'.format(
            task.name, evidence_.name))
    task.stub = self.celery.fexec.delay(task_runner, task, evidence_)


class PSQTaskManager(BaseTaskManager):
  """PSQ implementation of BaseTaskManager.

  Attributes:
    psq: PSQ Queue object.
    server_pubsub: A PubSubClient object for receiving new evidence messages.
  """

  def __init__(self):
    self.psq = None
    self.server_pubsub = None
    config.LoadConfig()
    super(PSQTaskManager, self).__init__()

  def _backend_setup(self):
    log.debug(
        'Setting up PSQ Task Manager requirements on project {0:s}'.format(
            config.PROJECT))
    self.server_pubsub = turbinia_pubsub.TurbiniaPubSub(config.PUBSUB_TOPIC)
    self.server_pubsub.setup()
    psq_pubsub_client = pubsub.Client(project=config.PROJECT)
    datastore_client = datastore.Client(project=config.PROJECT)
    try:
      self.psq = psq.Queue(
          psq_pubsub_client,
          config.PSQ_TOPIC,
          storage=psq.DatastoreStorage(datastore_client))
    except GaxError as e:
      msg = 'Error creating PSQ Queue: {0:s}'.format(str(e))
      log.error(msg)
      raise turbinia.TurbiniaException(msg)

  def process_tasks(self):
    completed_tasks = []
    for task in self.tasks:
      psq_task = task.stub.get_task()
      # This handles tasks that have failed at the PSQ layer.
      if not psq_task:
        log.debug('Task {0:s} not yet created'.format(task.stub.task_id))
      elif psq_task.status not in (psq.task.FINISHED, psq.task.FAILED):
        log.debug('Task {0:s} not finished'.format(psq_task.id))
      elif psq_task.status == psq.task.FAILED:
        log.warning('Task {0:s} failed.'.format(psq_task.id))
        completed_tasks.append(task)
      else:
        task.result = task.stub.result()
        completed_tasks.append(task)

    outstanding_task_count = len(self.tasks) - len(completed_tasks)
    log.info('{0:d} Tasks still outstanding.'.format(outstanding_task_count))
    # pylint: disable=expression-not-assigned
    return completed_tasks

  def get_evidence(self):
    requests = self.server_pubsub.check_messages()
    evidence_list = []
    for request in requests:
      for evidence_ in request.evidence:
        if not evidence_.request_id:
          evidence_.request_id = request.request_id
        log.info(
            'Received evidence [{0:s}] from PubSub message.'.format(
                str(evidence_)))
        evidence_list.append(evidence_)
    return evidence_list

  def enqueue_task(self, task, evidence_):
    log.info(
        'Adding PSQ task {0:s} with evidence {1:s} to queue'.format(
            task.name, evidence_.name))
    task.stub = self.psq.enqueue(task_runner, task, evidence_)
