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

import logging
from copy import deepcopy
from datetime import datetime
import time

from prometheus_client import Counter

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

if config.TASK_MANAGER.lower() == 'celery':
  from celery import states as celery_states
  from turbinia import tcelery as turbinia_celery

log = logging.getLogger(__name__)

# The amount of time in seconds that the Server will wait in addition to the
# Job/Task timeout value before it times out a given Task. This is to make sure
# that the Server doesn't time out the Task before the Worker has a chance to
# and should account for the Task scheduling and setup time that happens before
# the Task starts.  This time will be measured from the time the task is
# enqueue'd, not from when it actually starts on the worker so if there is a
# long wait for tasks to be executed they could potentially be timed out before
# even getting a chance to start so this limit is set conservatively high.
SERVER_TASK_TIMEOUT_BUFFER = 14400  # 4hr
# Amount of buffer time to give between task timeout and the celery soft timeout
# as we'd prefer for the task to timeout itself if possible so it has the most
# control over setting the correct results.  This should be caught in the
# `TurbiniaTask.run_wrapper()`.
CELERY_SOFT_TIMEOUT_BUFFER = 120
# Buffer time between task timeout and the hard celery timeout.  The hard
# timeout cannot be caught by the worker so we want to give the task timeout and
# soft timeout a chance for a graceful exit before falling back to this.
# Because the worker is killed it will not send any results back to the server
# and the server will have to time out the task there.
CELERY_HARD_TIMEOUT_BUFFER = 240

# Define metrics
turbinia_server_tasks_total = Counter(
    'turbinia_server_tasks_total', 'Turbinia Server Total Tasks')
turbinia_server_tasks_completed_total = Counter(
    'turbinia_server_tasks_completed_total',
    'Total number of completed server tasks')
turbinia_jobs_total = Counter(
    'turbinia_jobs_total', 'Total number jobs created')
turbinia_jobs_completed_total = Counter(
    'turbinia_jobs_completed_total', 'Total number jobs resolved')
turbinia_server_request_total = Counter(
    'turbinia_server_request_total', 'Total number of requests received.')
turbinia_server_task_timeout_total = Counter(
    'turbinia_server_task_timeout_total',
    'Total number of Tasks that have timed out on the Server.')
turbinia_result_success_invalid = Counter(
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
  if config.TASK_MANAGER.lower() == 'celery':
    return CeleryTaskManager()
  else:
    msg = f'Task Manager type "{config.TASK_MANAGER:s}" not implemented'
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
    # Both client and server isntances of the task  manager require backends.
    self._backend_setup(*args, **kwargs)
    # Only server instances of the task manager need to set up jobs.
    if kwargs.get('server') is False:
      return
    job_names = jobs_manager.JobsManager.GetJobNames()
    if jobs_denylist or jobs_allowlist:
      selected_jobs = jobs_denylist or jobs_allowlist
      for job in selected_jobs:
        if job.lower() not in job_names:
          msg = (
              f'Error creating server. Job {job} is not found in registered'
              f' jobs {job_names}')
          log.error(msg)
          raise TurbiniaException(msg)
      log.info(
          f'Filtering Jobs with allowlist {jobs_allowlist} and denylist '
          f'{jobs_denylist}')
      job_names = jobs_manager.JobsManager.FilterJobNames(
          job_names, jobs_denylist, jobs_allowlist)

    # Disable any jobs from the config that were not previously allowlisted.
    disabled_jobs = list(config.DISABLED_JOBS) if config.DISABLED_JOBS else []
    disabled_jobs = [j.lower() for j in disabled_jobs]
    if jobs_allowlist:
      disabled_jobs = list(set(disabled_jobs) - set(jobs_allowlist))
    if disabled_jobs:
      log.info(
          f'Disabling non-allowlisted jobs configured to be disabled in '
          f'the config file: {", ".join(disabled_jobs)}')
      job_names = jobs_manager.JobsManager.FilterJobNames(
          job_names, disabled_jobs, [])

    self.jobs = [job for _, job in jobs_manager.JobsManager.GetJobs(job_names)]
    dependencies = config.ParseDependencies()
    job_utils.register_job_timeouts(dependencies)
    log.debug(f'Registered job list: {str(job_names):s}')

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
    result.status = (
        f'Processing request for {evidence_name:s} aborted: {message:s}')
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
    log.info(f'Adding new evidence: {str(evidence_):s}')
    job_count = 0
    jobs_list = []

    jobs_allowlist = evidence_.config['globals'].get('jobs_allowlist', [])
    jobs_denylist = evidence_.config['globals'].get('jobs_denylist', [])
    if jobs_denylist or jobs_allowlist:
      log.info(
          f'Filtering Jobs with allowlist {jobs_allowlist} and denylist '
          f'{jobs_denylist}')
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
            f'Adding {job_instance.name:s} job to process {evidence_.name:s}')
        job_count += 1
        turbinia_jobs_total.inc()

    if isinstance(evidence_, evidence.Evidence):
      try:
        evidence_.validate_attributes()
      except TurbiniaException as exception:
        log.error(f'Error writing new evidence to redis: {exception}')
      else:
        self.state_manager.write_evidence(evidence_.serialize(json_values=True))

    if not job_count:
      log.warning(
          f'No Jobs/Tasks were created for Evidence {str(evidence_)}. '
          f'Request or recipe parsing may have failed, or Jobs may need to be '
          f'configured to allow this type of Evidence as input')

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
        f'Request {request_id} done, but not finalized, creating '
        f'FinalizeRequestJob{final_job.id}')

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
      job: The TurbiniaJob that created this Task.
      evidence_: An Evidence object to be processed.
    """
    if evidence_.request_id:
      task.request_id = evidence_.request_id
    elif job and job.request_id:
      task.request_id = job.request_id
    else:
      log.error(
          f'Request ID not found in Evidence {evidence_} or Task {task}.'
          f' Not adding new Task because of undefined state')
      return

    evidence_.config = job.evidence.config
    task.evidence_name = evidence_.name
    task.evidence_id = evidence_.id
    task.base_output_dir = config.OUTPUT_DIR
    task.requester = evidence_.config.get('globals', {}).get('requester')
    task.group_name = evidence_.config.get('globals', {}).get('group_name')
    task.reason = evidence_.config.get('globals', {}).get('reason')
    task.group_id = evidence_.config.get('globals', {}).get('group_id')
    if job:
      task.job_id = job.id
      task.job_name = job.name
      job.tasks.append(task)
    self.state_manager.write_new_task(task)
    timeout_limit = jobs_manager.JobsManager.GetTimeoutValue(task.job_name)
    self.enqueue_task(task, evidence_, timeout_limit)
    turbinia_server_tasks_total.inc()
    if task.id not in evidence_.tasks:
      evidence_.tasks.append(task.id)

  def remove_jobs(self, request_id):
    """Removes the all Jobs for the given request ID.

    Args:
      request_id (str): The ID of the request we want to remove jobs for.
    """
    remove_jobs = [j for j in self.running_jobs if j.request_id == request_id]
    log.debug(
        f'Removing {len(remove_jobs)} completed Job(s) for request ID '
        f'{request_id}.')
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

  def enqueue_task(self, task, evidence_, timeout_limit):
    """Enqueues a task and evidence in the implementation specific task queue.

    Args:
      task: An instantiated Turbinia Task
      evidence_: An Evidence object to be processed.
      timeout_limit(int): The timeout for the Task in seconds.
    """
    raise NotImplementedError

  def process_result(self, task_result):
    """Runs final task results recording.

    self.process_tasks handles things that have failed at the task queue layer
    (i.e. Celery), and this method handles tasks that have potentially failed
    below that layer (i.e. somewhere in our Task code).

    This also adds the Evidence to the running jobs and running requests so we
    can process those later in 'finalize' Tasks.

    Args:
      task_result: The TurbiniaTaskResult object
    """
    if task_result.successful is None:
      log.error(
          f'''Task {task_result.task_name} from {task_result.worker_name}
          returned invalid success status "None". Setting this to False
          so the client knows the Task is complete. Usually this means
          that the Task returning the TurbiniaTaskResult did not call
          the close() method on it.
        ''')
      turbinia_result_success_invalid.inc()
      task_result.successful = False
      if task_result.status:
        task_result.status = (
            task_result.status + ' (Success status forcefully set to False)')

    if not task_result.successful:
      log.error(
          f'Task {task_result.task_id} {task_result.task_name} '
          f'from {task_result.worker_name} was not successful')
    else:
      log.info(
          f'Task {task_result.task_id} {task_result.task_name} '
          f'from {task_result.worker_name} executed with status [{task_result.status}]'
      )

    if not isinstance(task_result.evidence, list):
      log.warning(
          f'Task {task_result.task_id} {task_result.task_name} '
          f'from {task_result.worker_name}did not return evidence list')
      task_result.evidence = []

    job = self.get_job(task_result.job_id)
    if not job:
      log.warning(
          f'Received task results for unknown Job from Task ID '
          f'{task_result.task_id:s}')

    # Reprocess new evidence and save instance for later consumption by finalize
    # tasks.
    for evidence_ in task_result.evidence:
      if isinstance(evidence_, evidence.Evidence):
        log.info(
            f'Task {task_result.task_name} from {task_result.worker_name} '
            f'returned Evidence {evidence_.name}')
        self.add_evidence(evidence_)
        if job:
          job.evidence.add_evidence(evidence_)
      else:
        log.error(
            f'Task {task_result.task_name} from {task_result.worker_name} '
            f'returned non-Evidence output type {type(task_result.evidence)}')

  def process_job(self, job, task):
    """Processes the Job after Task completes.

    This removes the Task from the running Job and generates the "finalize"
    Tasks after all the Tasks for the Job and Request have completed.  It also
    removes all Jobs from the running Job list once everything is complete.

    Args:
      job (TurbiniaJob): The Job to process
      task (TurbiniaTask): The Task that just completed.
    """
    log.debug(f'Processing Job {job.name:s} for completed Task {task.id:s}')
    job.remove_task(task.id)
    turbinia_server_tasks_completed_total.inc()
    if job.check_done() and not (job.is_finalize_job or task.is_finalize_task):
      log.debug(f'Job {job.name:s} completed, creating Job finalize tasks')
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
          self.process_result(task.result)
        job = self.get_job(task.job_id)
        if job:
          self.process_job(job, task)
        else:
          log.warning(
              f'Received task results for unknown Job {task.job_id} from Task '
              f'ID {task.id:s}')
        self.state_manager.update_task(task)

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
        f'Task {task.name} timed out on the Server and was '
        f'auto-closed after {timeout} seconds')
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
    self.kombu = turbinia_celery.TurbiniaKombu(config.KOMBU_CHANNEL)
    self.kombu.setup()
    if kwargs.get('server') is True:
      self.celery = turbinia_celery.TurbiniaCelery()
      self.celery.setup()
      self.celery_runner = self.celery.app.task(
          task_utils.task_runner, name='task_runner')

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
        log.debug(f'Task {task.stub.task_id:s} not yet created')
        check_timeout = True
      elif celery_task.status == celery_states.STARTED:
        log.debug(f'Task {celery_task.id:s} not finished')
        check_timeout = True
      elif celery_task.status == celery_states.FAILURE:
        log.warning(f'Task {celery_task.id:s} failed.')
        completed_tasks.append(task)
      elif celery_task.status == celery_states.SUCCESS:
        task.result = workers.TurbiniaTaskResult.deserialize(celery_task.result)
        completed_tasks.append(task)
      else:
        check_timeout = True
        log.debug(f'Task {celery_task.id:s} status unknown')

      # For certain Task states we want to check whether the Task has timed out
      # or not.
      if check_timeout:
        timeout = self.check_task_timeout(task)
        if timeout:
          log.warning(
              f'Task {celery_task.id} timed out on server after '
              f'{timeout} seconds. Auto-closing Task')
          task = self.timeout_task(task, timeout)
          completed_tasks.append(task)

    outstanding_task_count = len(self.tasks) - len(completed_tasks)
    if outstanding_task_count > 0:
      log.info(f'{outstanding_task_count:d} Tasks still outstanding.')
    return completed_tasks

  def get_evidence(self):
    """Receives new evidence.

    Returns:
      list[Evidence]: evidence to process.
    """
    requests = self.kombu.check_messages()
    evidence_list = []
    for request in requests:
      self.state_manager.write_request(
          deepcopy(request.to_json(json_values=True)))
      for evidence_ in request.evidence:
        if not evidence_.request_id:
          evidence_.request_id = request.request_id

        log.info(
            f'Received evidence [{str(evidence_):s}] with request ID '
            f'{request.request_id} from Kombu message.')

        success, message = recipe_helpers.validate_recipe(request.recipe)
        if not success:
          self.abort_request(
              evidence_.request_id, request.requester, evidence_.name, message)
        else:
          evidence_.config = request.recipe
          evidence_.config['globals']['requester'] = request.requester
          evidence_.config['globals']['group_name'] = request.group_name
          evidence_.config['globals']['reason'] = request.reason

          # A recipe could contain a group_id key so that tasks can be grouped
          # together, but this is optional. If the recipe doesn't specify a
          # group_id, then we grab it from the request object itself.
          try:
            recipe_group_id = request.recipe['globals']['group_id']
            if recipe_group_id:
              evidence_.config['globals']['group_id'] = recipe_group_id
          except KeyError:
            evidence_.config['globals']['group_id'] = request.group_id

          evidence_list.append(evidence_)
      turbinia_server_request_total.inc()

    return evidence_list

  def enqueue_task(self, task, evidence_, timeout):
    log.info(
        f'Adding Celery task {task.name:s} with evidence {evidence_.name:s}'
        f' to queue with base task timeout {timeout}')
    # https://docs.celeryq.dev/en/stable/userguide/configuration.html#task-time-limit
    # Hard limit in seconds, the worker processing the task will be killed and
    # replaced with a new one when this is exceeded.
    celery_soft_timeout = timeout + CELERY_SOFT_TIMEOUT_BUFFER
    celery_hard_timeout = timeout + CELERY_HARD_TIMEOUT_BUFFER
    self.celery_runner.max_retries = 0
    self.celery_runner.task_time_limit = celery_hard_timeout
    # Time limits described here:
    #     https://docs.celeryq.dev/en/stable/userguide/workers.html#time-limits
    task.stub = self.celery_runner.apply_async(
        (task.serialize(), evidence_.serialize()), retry=False,
        soft_time_limit=celery_soft_timeout, time_limit=celery_hard_timeout,
        expires=celery_hard_timeout)
