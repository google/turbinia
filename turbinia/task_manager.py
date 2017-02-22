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

import turbinia
from turbinia import config
from turbinia import pubsub


def get_task_manager():
  config.LoadConfig()
  if config.TASK_MANAGER == 'PubSub':
    return PubSubTaskManager()
  else:
    msg = u'Task Manager type "{0:s}" not implemented'.format(
        config.TASK_MANAGER)
    raise turbinia.TurbiniaException(msg)


class PubSubClient(object):
  pass


class TaskManager(object):

  def __init__(self):
    self.jobs = []
    # List of artifact objects to process
    self.artifacts = []

  def setup(self):
    """Does setup of Task manager dependencies."""
    self._backend_setup()

  def get_status(self):
    """Gets a status report of all running tasks.

    Returns:
      A human readable string of report data from the existing tasks and
      workers.
    """
    report_data = []
    report_data.append(u'Jobs:')
    report_data.append(u'\tName:\tActive Task:')
    for job in self.jobs:
      report_data.append(
          u'\t{0:s}\t{1:s}'.format(job.name, job.active_task.name))

    return '\n'.join(report_data)

  def add_artifact(self, artifact):
    """Add new artifact instance to process.

    Args:
      artifact: artifact object to add.
    """
    if not self.jobs:
      raise turbinia.TurbiniaException(
          u'Jobs must be registered before artifacts can be added')
    logging.info(u'Adding new artifact: {0:s}'.format(str(artifact)))
    self.artifacts.append(artifact)
    for job in self.jobs:
      if [True for t in job.artifact_input if isinstance(artifact, t)]:
        logging.info(u'Adding {0:s} job to queue to process {1:s}'.format(
            job.name, artifact.name))
        self.job_queue.append((job, artifact))

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

  def add_task(self
    raise NotImplementedError

  def process_jobs(self):
    # Check queue for jobs
    # Check for free task
    # Schedule job
    pass


class PubSubTaskManager(TaskManager):
  """PubSub implementation of TaskManager."""

  def __init__(self):
    self.workers = []
    config.LoadConfig()
    # Queue of (job, artifact) tuples to process.
    self.job_queue = []
    super(PubSubTaskManager, self).__init__()

  def _backend_setup(self):
    """Set up pubsub topics."""
    self.server_pubsub = pubsub.PubSubClient(config.PUBSUB_SERVER_TOPIC)
    self.worker_pubsub = pubsub.PubSubClient(config.PUBSUB_WORKER_TOPIC)


  def _send_message(self, message):
    # Wait for message here? or have queue of messages to ack?
    pass

  def _process_message(self, message):
    pass

  def _process_worker_message(self, message):
    """Process messages relating to worker start/stop/heartbeat."""
    pass

  def _process_task_message(self, message):
    """Process messages relating to task acceptance/update/completion."""
    # TODO(aarontp): fix
    if message[u'message_type'] == pubsub.TASKUPDATE:
      self._complete_task(message[u'job_id'], message[u'task_id'])
    elif message[u'message_type'] == pubsub.TASKSTART:
      self._complete_task(message[u'job_id'], message[u'task_id'])

  def _complete_task(self, job_id, task_id, result):
    # Set task to complete.
    job = self.get_job(job_id)
    job.active_task.result = result
    if not result.successful and job.tasks.get_next_task():
      logging.error(
          'Task {0:s} was not succesful, so not scheduling subsequent '
          'tasks'.format(task_id))
    if job.tasks.set_next_task():
      self.add_task(job.tasks.active_task)
    # Add output as new artifact to process
    # Check for child task and schedule.
    # If not child task, set job to complete.

  def add_worker(self, worker):
    self.worker.append(worker)

  def get_num_active_workers(self):
    return sum([1 for worker in self.workers if worker.in_use])

  def get_free_worker_count(self):
    return len(self.workers) - self.get_num_active_workers()

  def get_status(self):
    report_data = super(PubSubTaskManager, self).get_status().split('\n')
    report_data.append(u'Workers:')
    report_data.append(u'\tId:\tHostname:\tActive Job:')
    for worker in self.workers:
      job = self.get_job(worker.active_job)
      job_name = u'No Active Job' if not job else job.name
      report_data.append(u'\t{0:s}\t{1:s}\t{2:s}'.format(
          worker.id, worker.hostname, job_name))

    return '\n'.join(report_data)
