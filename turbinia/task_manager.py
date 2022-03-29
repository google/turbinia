#-*- coding: utf-8 -*-
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

from __future__ import unicode_literals, absolute_import

import logging
from datetime import datetime
import time
import os
import filelock

from prometheus_client import Gauge

import turbinia
from turbinia import workers
from turbinia import evidence
from turbinia import config
from turbinia import job_utils
from turbinia import state_manager
from turbinia import task_utils
from turbinia import TurbiniaException
from turbinia.jobs import manager as jobs_manager
from turbinia.lib import recipe_helpers
from turbinia.workers.abort import AbortTask

config.LoadConfig()
if config.TASK_MANAGER.lower() == 'psq':
  import psq

  from google.cloud import exceptions
  from google.cloud import datastore
  from google.cloud import pubsub

  from turbinia import pubsub as turbinia_pubsub
elif config.TASK_MANAGER.lower() == 'celery':
  from celery import states as celery_states

  from turbinia import tcelery as turbinia_celery

log = logging.getLogger('turbinia')

PSQ_TASK_TIMEOUT_SECONDS = 604800
PSQ_QUEUE_WAIT_SECONDS = 2
# The amount of time in seconds that the Server will wait in addition to the
# Job/Task timeout value before it times out a given Task. This is to make sure
# that the Server doesn't time out the Task before the Worker has a chance to
# and should account for the Task scheduling and setup time that happens before
# the Task starts.
SERVER_TASK_TIMEOUT_BUFFER = 300

# Define metrics
turbinia_server_tasks_total = Gauge(
    'turbinia_server_tasks_total', 'Turbinia Server Total Tasks')
turbinia_server_tasks_completed_total = Gauge(
    'turbinia_server_tasks_completed_total',
    'Total number of completed server tasks')
turbinia_jobs_total = Gauge('turbinia_jobs_total', 'Total number jobs created')
turbinia_jobs_completed_total = Gauge(
    'turbinia_jobs_completed_total', 'Total number jobs resolved')
turbinia_server_request_total = Gauge(
    'turbinia_server_request_total', 'Total number of requests received.')
turbinia_server_task_timeout_total = Gauge(
    'turbinia_server_task_timeout_total',
    'Total number of Tasks that have timed out on the Server.')
turbinia_result_success_invalid = Gauge(
    'turbinia_result_success_invalid',
    'The result returned from the Task had an invalid success status of None')


def get_task_manager():
  """Return task manager object based on config.

  Returns
    Initialized TaskManager object.

  Raises:
    TurbiniaException: When an unknown task manager type is specified
  """
  config.LoadConfig()
  # pylint: disable=no-else-return
  if config.TASK_MANAGER.lower() == 'psq':
    return PSQTaskManager()
  elif config.TASK_MANAGER.lower() == 'celery':
    return CeleryTaskManager()
  else:
    msg = 'Task Manager type "{0:s}" not implemented'.format(
        config.TASK_MANAGER)
    raise turbinia.TurbiniaException(msg)


class BaseTaskManager:
  """Class to manage Turbinia Tasks.

  Handles incoming new Evidence messages, adds new Tasks to the queue and
  processes results from Tasks that have run.

  Attributes:
    jobs (list[TurbiniaJob]): Uninstantiated job classes.
    running_jobs (list[TurbiniaJob]): A list of jobs that are
        currently running.
    evidence (list): A list of evidence objects to process.
    state_manager (DatastoreStateManager|RedisStateManager): State manager
        object to handle syncing with storage.
    tasks (list[TurbiniaTask]): Running tasks.
  """

  def __init__(self):
    self.jobs = []
    self.running_jobs = []
    self.state_manager = state_manager.get_state_manager()

  @property
  def tasks(self):
    """A property that returns all outstanding Tasks.

    Returns:
      list[TurbiniaTask]: All outstanding Tasks.
    """
    return [task for job in self.running_jobs for task in job.tasks]

  def _backend_setup(self, *args, **kwargs):
    """Sets up backend dependencies.

    Raises:
      TurbiniaException: When encountering fatal errors setting up dependencies.
    """
    raise NotImplementedError

  def setup(self, jobs_denylist=None, jobs_allowlist=None, *args, **kwargs):
    """Does setup of Task manager and its dependencies.

    Args:
      jobs_denylist (list): Jobs that will be excluded from running
      jobs_allowlist (list): The only Jobs will be included to run
    """
    self._backend_setup(*args, **kwargs)
    job_names = jobs_manager.JobsManager.GetJobNames()
    if jobs_denylist or jobs_allowlist:
      selected_jobs = jobs_denylist or jobs_allowlist
      for job in selected_jobs:
        if job.lower() not in job_names:
          msg = (
              'Error creating server. Job {0!s} is not found in registered '
              'jobs {1!s}.'.format(job, job_names))
          log.error(msg)
          raise TurbiniaException(msg)
      log.info(
          'Filtering Jobs with allowlist {0!s} and denylist {1!s}'.format(
              jobs_allowlist, jobs_denylist))
      job_names = jobs_manager.JobsManager.FilterJobNames(
          job_names, jobs_denylist, jobs_allowlist)

    # Disable any jobs from the config that were not previously allowlisted.
    disabled_jobs = list(config.DISABLED_JOBS) if config.DISABLED_JOBS else []
    disabled_jobs = [j.lower() for j in disabled_jobs]
    if jobs_allowlist:
      disabled_jobs = list(set(disabled_jobs) - set(jobs_allowlist))
    if disabled_jobs:
      log.info(
          'Disabling non-allowlisted jobs configured to be disabled in the '
          'config file: {0:s}'.format(', '.join(disabled_jobs)))
      job_names = jobs_manager.JobsManager.FilterJobNames(
          job_names, disabled_jobs, [])

    self.jobs = [job for _, job in jobs_manager.JobsManager.GetJobs(job_names)]
    dependencies = config.ParseDependencies()
    job_utils.register_job_timeouts(dependencies)
    log.debug('Registered job list: {0:s}'.format(str(job_names)))

  def abort_request(self, request_id, requester, evidence_name, message):
    """Abort the request by creating an AbortTask.

    When there is a fatal error processing the request such that we can't
    continue, an AbortTask will be created with the error message and is written
    directly to the state database. This way the client will get a reasonable
    error in response to the failure.
    
    Args:
      request_id(str): The request ID.
      requester(str): The username of the requester.
      evidence_name(str): Name of the Evidence requested to be processed.
      message(str): The error message to abort the request with.
    """
    abort_task = AbortTask(request_id=request_id, requester=requester)
    result = workers.TurbiniaTaskResult(
        request_id=request_id, no_output_manager=True)
    result.status = 'Processing request for {0:s} aborted: {1:s}'.format(
        evidence_name, message)
    result.successful = False
    abort_task.result = result
    self.state_manager.update_task(abort_task)

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
    job_count = 0
    jobs_list = []

    jobs_allowlist = evidence_.config['globals'].get('jobs_allowlist', [])
    jobs_denylist = evidence_.config['globals'].get('jobs_denylist', [])
    if jobs_denylist or jobs_allowlist:
      log.info(
          'Filtering Jobs with allowlist {0!s} and denylist {1!s}'.format(
              jobs_allowlist, jobs_denylist))
      jobs_list = jobs_manager.JobsManager.FilterJobObjects(
          self.jobs, jobs_denylist, jobs_allowlist)
    else:
      jobs_list = self.jobs

    # TODO(aarontp): Add some kind of loop detection in here so that jobs can
    # register for Evidence(), or or other evidence types that may be a super
    # class of the output of the job itself.  Short term we could potentially
    # have a run time check for this upon Job instantiation to prevent it.
    for job in jobs_list:
      # Doing a strict type check here for now until we can get the above
      # comment figured out.
      # pylint: disable=unidiomatic-typecheck
      job_applicable = [
          True for t in job.evidence_input if type(evidence_) == t
      ]

      if job_applicable:
        job_instance = job(
            request_id=evidence_.request_id, evidence_config=evidence_.config)

        for task in job_instance.create_tasks([evidence_]):
          self.add_task(task, job_instance, evidence_)

        self.running_jobs.append(job_instance)
        log.info(
            'Adding {0:s} job to process {1:s}'.format(
                job_instance.name, evidence_.name))
        job_count += 1
        turbinia_jobs_total.inc()

    if not job_count:
      log.warning(
          'No Jobs/Tasks were created for Evidence [{0:s}]. '
          'Request or recipe parsing may have failed, or Jobs may need to be '
          'configured to allow this type of Evidence as input'.format(
              str(evidence_)))

  def check_done(self):
    """Checks if we have any outstanding tasks.

    Returns:
      bool: Indicating whether we are done.
    """
    return not bool(len(self.tasks))

  def check_request_done(self, request_id):
    """Checks if we have any outstanding tasks for the request ID.

    Args:
      request_id (str): The request ID to check for completion

    Returns:
      bool: Indicating whether all Jobs are done.
    """
    job_completion = []
    for job in self.running_jobs:
      if request_id == job.request_id:
        job_completion.append(job.check_done())

    return min(job_completion)

  def check_request_finalized(self, request_id):
    """Checks if the the request is done and finalized.

    A request can be done but not finalized if all of the Tasks created by the
    original Jobs have completed, but the "finalize" Job/Tasks have not been
    run.  These finalize Job/Tasks are created after all of the original
    Jobs/Tasks have completed. Only one Job needs to be marked as finalized for
    the entire request to be considered finalized.

    Args:
      request_id (str): The request ID to check for finalization.

    Returns:
      bool: Indicating whether all Jobs are done.
    """
    request_finalized = False
    for job in self.running_jobs:
      if request_id == job.request_id and job.is_finalized:
        request_finalized = True
        break

    return request_finalized and self.check_request_done(request_id)

  def check_task_timeout(self, task):
    """Checks whether a Task has timed out.

    Tasks should normally be timed out by the Worker, but if there was some
    kind of fatal error on the Worker or other problem in the Task that
    prevented the results from returning then we will time out on the Server
    side as well and abandon the Task.

    Args:
      task(TurbiniaTask): The Task to check for the timeout.

    Returns:
      int: If the Task has timed out, this is the time in seconds, otherwise if
          the Task hasn't timed out it will return 0.
    """
    job = self.get_job(task.job_id)
    timeout_target = jobs_manager.JobsManager.GetTimeoutValue(job.name)
    task_runtime = datetime.now() - task.start_time
    task_runtime = int(task_runtime.total_seconds())
    if task_runtime > timeout_target + SERVER_TASK_TIMEOUT_BUFFER:
      timeout = task_runtime
    else:
      timeout = 0

    return timeout

  def get_evidence(self):
    """Checks for new evidence to process.

    Returns:
      list[evidence.Evidence]: The evidence to process.
    """
    raise NotImplementedError

  def get_job(self, job_id):
    """Gets the running Job instance from the given Job ID

    Args:
      job_id (str): The Job id to get the job for.

    Returns:
      TurbiniaJob|None: Job instance if found, else None
    """
    job = None
    for job_instance in self.running_jobs:
      if job_id == job_instance.id:
        job = job_instance
        break

    return job

  def generate_request_finalize_tasks(self, job):
    """Generates the Tasks to finalize the given request ID.

    Args:
      job (TurbiniaJob): The last Job that was run for this request.
    """
    request_id = job.request_id
    final_job = jobs_manager.JobsManager.GetJobInstance('FinalizeRequestJob')
    final_job.request_id = request_id
    final_job.evidence.config = job.evidence.config
    log.debug(
        'Request {0:s} done, but not finalized, creating FinalizeRequestJob '
        '{1:s}'.format(request_id, final_job.id))

    # Finalize tasks use EvidenceCollection with all evidence created by the
    # request or job.
    final_evidence = evidence.EvidenceCollection()
    final_evidence.request_id = request_id
    self.running_jobs.append(final_job)
    turbinia_jobs_total.inc()
    # Gather evidence created by every Job in the request.
    for running_job in self.running_jobs:
      if running_job.request_id == request_id:
        final_evidence.collection.extend(running_job.evidence.collection)

    for finalize_task in final_job.create_tasks([final_evidence]):
      self.add_task(finalize_task, final_job, final_evidence)

  def add_task(self, task, job, evidence_):
    """Adds a task and evidence to process to the task manager.

    Args:
      task: An instantiated Turbinia Task
      evidence_: An Evidence object to be processed.
    """
    if evidence_.request_id:
      task.request_id = evidence_.request_id
    elif job and job.request_id:
      task.request_id = job.request_id
    else:
      log.error(
          'Request ID not found in Evidence {0!s} or Task {1!s}. Not adding '
          'new Task because of undefined state'.format(evidence_, task))
      return

    evidence_.config = job.evidence.config
    task.base_output_dir = config.OUTPUT_DIR
    task.requester = evidence_.config.get('globals', {}).get('requester')
    task.group_id = evidence_.config.get('globals', {}).get('group_id')
    if job:
      task.job_id = job.id
      task.job_name = job.name
      job.tasks.append(task)
    self.state_manager.write_new_task(task)
    self.enqueue_task(task, evidence_)
    turbinia_server_tasks_total.inc()

  def remove_jobs(self, request_id):
    """Removes the all Jobs for the given request ID.

    Args:
      request_id (str): The ID of the request we want to remove jobs for.
    """
    remove_jobs = [j for j in self.running_jobs if j.request_id == request_id]
    log.debug(
        'Removing {0:d} completed Job(s) for request ID {1:s}.'.format(
            len(remove_jobs), request_id))
    # pylint: disable=expression-not-assigned
    [self.remove_job(j.id) for j in remove_jobs]

  def remove_job(self, job_id):
    """Removes a Job from the running jobs list.

    Args:
      job_id (str): The ID of the job to remove.

    Returns:
      bool: True if Job removed, else False.
    """
    remove_job = None
    for job in self.running_jobs:
      if job_id == job.id:
        remove_job = job
        break

    if remove_job:
      self.running_jobs.remove(remove_job)
      turbinia_jobs_completed_total.inc()
    return bool(remove_job)

  def enqueue_task(self, task, evidence_):
    """Enqueues a task and evidence in the implementation specific task queue.

    Args:
      task: An instantiated Turbinia Task
      evidence_: An Evidence object to be processed.
    """
    raise NotImplementedError

  def process_result(self, task_result):
    """Runs final task results recording.

    self.process_tasks handles things that have failed at the task queue layer
    (i.e. PSQ), and this method handles tasks that have potentially failed
    below that layer (i.e. somewhere in our Task code).

    This also adds the Evidence to the running jobs and running requests so we
    can process those later in 'finalize' Tasks.

    Args:
      task_result: The TurbiniaTaskResult object

    Returns:
      TurbiniaJob|None: The Job for the processed task, else None
    """
    if task_result.successful is None:
      log.error(
          'Task {0:s} from {1:s} returned invalid success status "None". '
          'Setting this to False so the client knows the Task is complete. '
          'Usually this means that the Task returning the TurbiniaTaskResult '
          'did not call the close() method on it.'.format(
              task_result.task_name, task_result.worker_name))
      turbinia_result_success_invalid.inc()
      task_result.successful = False
      if task_result.status:
        task_result.status = (
            task_result.status + ' (Success status forcefully set to False)')

    if not task_result.successful:
      log.error(
          'Task {0:s} from {1:s} was not successful'.format(
              task_result.task_name, task_result.worker_name))
    else:
      log.info(
          'Task {0:s} from {1:s} executed with status [{2:s}]'.format(
              task_result.task_name, task_result.worker_name,
              task_result.status))

    if not isinstance(task_result.evidence, list):
      log.warning(
          'Task {0:s} from {1:s} did not return evidence list'.format(
              task_result.task_name, task_result.worker_name))
      task_result.evidence = []

    job = self.get_job(task_result.job_id)
    if not job:
      log.warning(
          'Received task results for unknown Job from Task ID {0:s}'.format(
              task_result.task_id))

    # Reprocess new evidence and save instance for later consumption by finalize
    # tasks.
    for evidence_ in task_result.evidence:
      if isinstance(evidence_, evidence.Evidence):
        log.info(
            'Task {0:s} from {1:s} returned Evidence {2:s}'.format(
                task_result.task_name, task_result.worker_name, evidence_.name))
        self.add_evidence(evidence_)
        if job:
          job.evidence.add_evidence(evidence_)
      else:
        log.error(
            'Task {0:s} from {1:s} returned non-Evidence output type '
            '{2:s}'.format(
                task_result.task_name, task_result.worker_name,
                type(task_result.evidence)))

    return job

  def process_job(self, job, task):
    """Processes the Job after Task completes.

    This removes the Task from the running Job and generates the "finalize"
    Tasks after all the Tasks for the Job and Request have completed.  It also
    removes all Jobs from the running Job list once everything is complete.

    Args:
      job (TurbiniaJob): The Job to process
      task (TurbiniaTask): The Task that just completed.
    """
    log.debug(
        'Processing Job {0:s} for completed Task {1:s}'.format(
            job.name, task.id))
    self.state_manager.update_task(task)
    job.remove_task(task.id)
    turbinia_server_tasks_completed_total.inc()
    if job.check_done() and not (job.is_finalize_job or task.is_finalize_task):
      log.debug(
          'Job {0:s} completed, creating Job finalize tasks'.format(job.name))
      final_task = job.create_final_task()
      if final_task:
        final_task.is_finalize_task = True
        self.add_task(final_task, job, job.evidence)
        turbinia_server_tasks_total.inc()
    elif job.check_done() and job.is_finalize_job:
      job.is_finalized = True

    request_id = job.request_id
    request_done = self.check_request_done(request_id)
    request_finalized = self.check_request_finalized(request_id)
    # If the request is done but not finalized, we generate the finalize tasks.
    if request_done and not request_finalized:
      self.generate_request_finalize_tasks(job)

    # If the Job has been finalized then we can remove all the Jobs for this
    # request since everything is complete.
    elif request_done and request_finalized:
      self.remove_jobs(request_id)

  def process_tasks(self):
    """Process any tasks that need to be processed.

    Returns:
      list[TurbiniaTask]: Tasks to process that have completed.
    """
    raise NotImplementedError

  def run(self, under_test=False):
    """Main run loop for TaskManager."""
    log.info('Starting Task Manager run loop')
    while True:
      # pylint: disable=expression-not-assigned
      [self.add_evidence(x) for x in self.get_evidence()]

      for task in self.process_tasks():
        if task.result:
          job = self.process_result(task.result)
          if job:
            self.process_job(job, task)
        self.state_manager.update_task(task)

      if config.SINGLE_RUN and self.check_done():
        log.info('No more tasks to process.  Exiting now.')
        return

      if under_test:
        break

      time.sleep(config.SLEEP_TIME)

  def timeout_task(self, task, timeout):
    """Sets status and result data for timed out Task.

    Args:
      task(TurbiniaTask): The Task that will be timed out.
      timeout(int): The timeout value that has been reached.

    Returns:
      TurbiniaTask: The updated Task.
    """
    result = workers.TurbiniaTaskResult(
        request_id=task.request_id, no_output_manager=True,
        no_state_manager=True)
    result.setup(task)
    result.status = (
        'Task {0:s} timed out on the Server and was auto-closed after '
        '{1:d} seconds'.format(task.name, timeout))
    result.successful = False
    result.closed = True
    task.result = result
    turbinia_server_task_timeout_total.inc()

    return task


class CeleryTaskManager(BaseTaskManager):
  """Celery implementation of BaseTaskManager.

  Attributes:
    celery (TurbiniaCelery): Celery task queue, handles worker tasks.
    kombu (TurbiniaKombu): Kombu queue, handles receiving evidence.
    celery_runner: task_runner method, but wrapped for Celery usage.
  """

  def __init__(self):
    self.celery = None
    self.kombu = None
    self.celery_runner = None
    config.LoadConfig()
    super(CeleryTaskManager, self).__init__()

  def _backend_setup(self, *args, **kwargs):
    self.celery = turbinia_celery.TurbiniaCelery()
    self.celery.setup()
    self.kombu = turbinia_celery.TurbiniaKombu(config.KOMBU_CHANNEL)
    self.kombu.setup()
    self.celery_runner = self.celery.app.task(
        task_utils.task_runner, name="task_runner")

  def process_tasks(self):
    """Determine the current state of our tasks.

    Returns:
      list[TurbiniaTask]: all completed tasks
    """
    completed_tasks = []
    for task in self.tasks:
      check_timeout = False
      celery_task = task.stub
      if not celery_task:
        log.debug('Task {0:s} not yet created'.format(task.stub.task_id))
        check_timeout = True
      elif celery_task.status == celery_states.STARTED:
        log.debug('Task {0:s} not finished'.format(celery_task.id))
        check_timeout = True
      elif celery_task.status == celery_states.FAILURE:
        log.warning('Task {0:s} failed.'.format(celery_task.id))
        completed_tasks.append(task)
      elif celery_task.status == celery_states.SUCCESS:
        task.result = workers.TurbiniaTaskResult.deserialize(celery_task.result)
        completed_tasks.append(task)
      else:
        check_timeout = True
        log.debug('Task {0:s} status unknown'.format(celery_task.id))

      # For certain Task states we want to check whether the Task has timed out
      # or not.
      if check_timeout:
        timeout = self.check_task_timeout(task)
        if timeout:
          log.warning(
              'Task {0:s} timed out on server after {1:d} seconds. '
              'Auto-closing Task.'.format(celery_task.id, timeout))
          task = self.timeout_task(task, timeout)
          completed_tasks.append(task)

    outstanding_task_count = len(self.tasks) - len(completed_tasks)
    if outstanding_task_count > 0:
      log.info('{0:d} Tasks still outstanding.'.format(outstanding_task_count))
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

        success, message = recipe_helpers.validate_recipe(request.recipe)
        if not success:
          self.abort_request(
              evidence_.request_id, request.requester, evidence_.name, message)
        else:
          evidence_.config = request.recipe
          evidence_.config['globals']['requester'] = request.requester
          evidence_.config['globals']['group_id'] = request.recipe['globals'][
              'group_id']
          evidence_list.append(evidence_)
      turbinia_server_request_total.inc()

    return evidence_list

  def enqueue_task(self, task, evidence_):
    log.info(
        'Adding Celery task {0:s} with evidence {1:s} to queue'.format(
            task.name, evidence_.name))
    task.stub = self.celery_runner.delay(
        task.serialize(), evidence_.serialize())


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

  # pylint: disable=keyword-arg-before-vararg
  def _backend_setup(self, server=True, *args, **kwargs):
    """
    Args:
      server (bool): Whether this is the client or a server

    Raises:
      TurbiniaException: When there are errors creating PSQ Queue
    """

    log.debug(
        'Setting up PSQ Task Manager requirements on project {0:s}'.format(
            config.TURBINIA_PROJECT))
    self.server_pubsub = turbinia_pubsub.TurbiniaPubSub(config.PUBSUB_TOPIC)
    if server:
      self.server_pubsub.setup_subscriber()
    else:
      self.server_pubsub.setup_publisher()
    psq_publisher = pubsub.PublisherClient()
    psq_subscriber = pubsub.SubscriberClient()
    datastore_client = datastore.Client(project=config.TURBINIA_PROJECT)
    try:
      self.psq = psq.Queue(
          psq_publisher, psq_subscriber, config.TURBINIA_PROJECT,
          name=config.PSQ_TOPIC, storage=psq.DatastoreStorage(datastore_client))
    except exceptions.GoogleCloudError as e:
      msg = 'Error creating PSQ Queue: {0:s}'.format(str(e))
      log.error(msg)
      raise turbinia.TurbiniaException(msg)

  def process_tasks(self):
    completed_tasks = []
    for task in self.tasks:
      check_timeout = False
      psq_task = task.stub.get_task()
      # This handles tasks that have failed at the PSQ layer.
      if not psq_task:
        check_timeout = True
        log.debug('Task {0:s} not yet created'.format(task.stub.task_id))
      elif psq_task.status not in (psq.task.FINISHED, psq.task.FAILED):
        check_timeout = True
        log.debug('Task {0:s} not finished'.format(psq_task.id))
      elif psq_task.status == psq.task.FAILED:
        log.warning('Task {0:s} failed.'.format(psq_task.id))
        completed_tasks.append(task)
      else:
        task.result = workers.TurbiniaTaskResult.deserialize(
            task.stub.result(timeout=PSQ_TASK_TIMEOUT_SECONDS))
        completed_tasks.append(task)

      # For certain Task states we want to check whether the Task has timed out
      # or not.
      if check_timeout:
        timeout = self.check_task_timeout(task)
        if timeout:
          log.warning(
              'Task {0:s} timed on server out after {0:d} seconds. Auto-closing Task.'
              .format(task.id, timeout))
          task = self.timeout_task(task, timeout)
          completed_tasks.append(task)

    outstanding_task_count = len(self.tasks) - len(completed_tasks)
    if outstanding_task_count > 0:
      log.info('{0:d} Tasks still outstanding.'.format(outstanding_task_count))
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

        success, message = recipe_helpers.validate_recipe(request.recipe)
        if not success:
          self.abort_request(
              evidence_.request_id, request.requester, evidence_.name, message)
        else:
          evidence_.config = request.recipe
          evidence_.config['globals']['requester'] = request.requester
          evidence_list.append(evidence_)
      turbinia_server_request_total.inc()

    return evidence_list

  def enqueue_task(self, task, evidence_):
    log.info(
        'Adding PSQ task {0:s} with evidence {1:s} to queue'.format(
            task.name, evidence_.name))
    task.stub = self.psq.enqueue(
        task_utils.task_runner, task.serialize(), evidence_.serialize())
    time.sleep(PSQ_QUEUE_WAIT_SECONDS)
