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

import logging
import time

import psq
from google.cloud import datastore
from google.cloud import pubsub

import turbinia
from turbinia import evidence
from turbinia import config
from turbinia import jobs
from turbinia import pubsub as turbinia_pubsub


def get_task_manager():
  config.LoadConfig()
  if config.TASK_MANAGER == 'PSQ':
    return PSQTaskManager()
  else:
    msg = u'Task Manager type "{0:s}" not implemented'.format(
        config.TASK_MANAGER)
    raise turbinia.TurbiniaException(msg)


def task_runner(obj, *args, **kwargs):
  # TODO(aarontp): Add proper error checks/handling
  return obj.run(*args, **kwargs)


class TaskManager(object):

  def __init__(self):
    # Registered and instantiated job objects
    self.jobs = []
    # List of evidence objects to process
    self.evidence = []

  def setup(self):
    """Does setup of Task manager and its dependencies."""
    self._backend_setup()
    self.jobs = jobs.GetJobs()

  def add_evidence(self, evidence):
    """Add new evidence instance to process.

    This creates a new task for each Job that has this Evidence type as an
    input.

    Args:
      evidence: evidence object to add.
    """
    if not self.jobs:
      raise turbinia.TurbiniaException(
          u'Jobs must be registered before evidence can be added')
    logging.info(u'Adding new evidence: {0:s}'.format(str(evidence)))
    self.evidence.append(evidence)
    for job in self.jobs:
      if [True for t in job.evidence_input if isinstance(evidence, t)]:
        logging.info(u'Adding {0:s} job to process {1:s}'.format(
            job.name, evidence.name))
        self.add_task(job.create_task(), evidence)

  def get_evidence(self):
    """Checks for new evidence.

    Returns:
      A list of Evidence objects
    """
    raise NotImplementedError

  def add_job(self, job):
    # TODO(aarontp): Insert jobs according to priority
    self.jobs.append(job)

  def get_job(self, job_id):
    """Returns an active job instance for a given job id.

    Args:
      job_id: The id of the job to search for.

    Returns:
      Job object if job is found, else None.
    """
    for job in self.jobs:
      if self.job.id == job_id:
        return job
    return None

  def add_task(self, task=None, evidence=None):
    raise NotImplementedError

  def process_tasks(self):
    """Process any tasks that need to be processed."""
    raise NotImplementedError

  def run(self):
    while True:
      # pylint: disable=expression-not-assigned
      [self.add_evidence(x) for x in self.get_evidence()]
      self.process_tasks()
      # TODO(aarontp): Add config var for this.
      time.sleep(30)


class PSQTaskManager(TaskManager):
  """PSQ implementation of TaskManager."""

  def __init__(self):
    self.task_results = []
    config.LoadConfig()
    super(PSQTaskManager, self).__init__()

  def _backend_setup(self):
    """Set up backend dependencies."""
    self.server_pubsub = turbinia_pubsub.PubSubClient(config.PUBSUB_TOPIC)
    psq_pubsub_client = pubsub.Client(project=config.PROJECT)
    datastore_client = datastore.Client(project=config.PROJECT)
    self.psq = psq.Queue(
        psq_pubsub_client, config.PSQ_TOPIC,
        storage=psq.DatastoreStorage(datastore_client))

  def _complete_task(self, psq_task, task):
    """Runs final task data recording.

    Args:
      psq_task: An instance of the psq_task that ran
      task: The Turbinia Task object
    """
    # TODO(aarontp): Make sure this is set by the task
    if not task.result.successful:
      logging.error('Task {0:s} was not succesful'.format(task.name))
    else:
      logging.info('Task {0:s} executed with status {1:d}'.format(
          task.name, task.result))

    # Add output as new evidence to process
    if not task.output:
      logging.info('Task {0:s} did not return output'.format(task.name))
    elif isinstance(task.output, evidence.Evidence):
      logging.info('Task {0:s} returned non-Evidence output type {1:s}'.format(
          task.name, type(task.output)))
    else:
      self.add_evidence(task.output)

  def process_tasks(self):
    """Checks for tasks that have completed.

    Returns:
      The number of tasks that have completed.
    """
    completed_tasks = []
    for result in self.task_results:
      psq_task = result.get_task()
      if not psq_task:
        logging.debug('Task {0:d} not yet created'.format(result.task_id))
      elif psq_task.status not in (psq.task.FINISHED, psq.task.FAILED):
        logging.debug('Task {0:d} still running').format(psq_task.id)
      elif psq_task.status == psq.task.FAILED:
        logging.debug('Task {0:d} failed.').format(psq_task.id)
        # TODO(aarontp): handle failures
      else:
        output = result.result()
        completed_tasks.append(result)
        self._complete_task(psq_task, output)

    # pylint: disable=expression-not-assigned
    return len([self.task_results.pop(task) for task in completed_tasks])

  def get_evidence(self):
    # Check pubsub for new evidence messages
    pass

  def add_task(self, task, evidence_):
    """Adds a task to be queued along with the evidence it will process.

    Args:
      task: A Turbinia Task
      evidence: An Evidence object to be processed.
    """
    logging.info('Adding task {0:s} with evidence {1:s} to queue').format(
        task.name, evidence_.name)
    self.task_results.append(self.psq.enqueue(task_runner(task, evidence_)))


class PubSubTaskManager(TaskManager):

  def _process_task_message(self, message):
    """Process messages relating to task acceptance/update/completion."""
    # TODO(aarontp): fix
    if message[u'message_type'] == pubsub.TASKUPDATE:
      self._complete_task(message[u'job_id'], message[u'task_id'])
    elif message[u'message_type'] == pubsub.TASKSTART:
      self._complete_task(message[u'job_id'], message[u'task_id'])

  def add_worker(self, worker):
    self.worker.append(worker)

  def get_num_active_workers(self):
    return sum([1 for worker in self.workers if worker.in_use])

  def get_free_worker_count(self):
    return len(self.workers) - self.get_num_active_workers()

  def get_status(self):
    report_data = []
    report_data.append(u'Jobs:')
    report_data.append(u'\tName:\tActive Task:')
    for job in self.jobs:
      report_data.append(
          u'\t{0:s}\t{1:s}'.format(job.name, job.active_task.name))

    report_data.append(u'Workers:')
    report_data.append(u'\tId:\tHostname:\tActive Job:')
    for worker in self.workers:
      job = self.get_job(worker.active_job)
      job_name = u'No Active Job' if not job else job.name
      report_data.append(u'\t{0:s}\t{1:s}\t{2:s}'.format(
          worker.id, worker.hostname, job_name))

    return '\n'.join(report_data)

