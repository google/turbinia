# -*- coding: utf-8 -*-
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
"""Client objects for Turbinia."""

from collections import defaultdict
from datetime import datetime
from datetime import timedelta

import logging
from operator import itemgetter
from operator import attrgetter
import os
import time

from turbinia import config
from turbinia.config import logger
from turbinia.config import DATETIME_FORMAT
from turbinia import task_manager
from turbinia import TurbiniaException
from turbinia.lib import recipe_helpers
from turbinia.lib import text_formatter as fmt
from turbinia.message import TurbiniaRequest
from turbinia.workers import Priority, TurbiniaTask

MAX_RETRIES = 10
RETRY_SLEEP = 60

config.LoadConfig()
if config.CLOUD_PROVIDER.lower() == 'gcp':
  from libcloudforensics.providers.gcp.internal import function as gcp_function
if config.TASK_MANAGER.lower() == 'celery':
  from turbinia.state_manager import RedisStateManager

log = logging.getLogger(__name__)


def setup(is_client=False):
  config.LoadConfig()
  if is_client:
    logger.setup(need_file_handler=False)
  else:
    logger.setup()


def get_turbinia_client():
  """Return Turbinia client based on config.

  Returns:
    Initialized BaseTurbiniaClient or TurbiniaCeleryClient object.
  """
  # pylint: disable=no-else-return
  setup(is_client=True)
  if config.TASK_MANAGER.lower() == 'celery':
    return TurbiniaCeleryClient()
  else:
    msg = f'Task Manager type "{config.TASK_MANAGER:s}" not implemented'
    raise TurbiniaException(msg)


class TurbiniaStats:
  """Statistics for Turbinia task execution.

  Attributes:
    count(int): The number of tasks
    min(datetime.timedelta): The minimum run time of all tasks
    max(datetime.timedelta): The maximum run time of all tasks
    mean(datetime.timedelta): The mean run time of all tasks
    tasks(list): A list of tasks to calculate stats for
  """

  def __init__(self, description=None):
    self.description = description
    self.min = None
    self.mean = None
    self.max = None
    self.tasks = []

  def __str__(self):
    return self.format_stats()

  @property
  def count(self):
    """Gets a count of the tasks in this stats object.

    Returns:
      Int of task count.
    """
    return len(self.tasks)

  def add_task(self, task):
    """Add a task result dict.

    Args:
      task(dict): The task results we want to count stats for.
    """
    self.tasks.append(task)

  def calculate_stats(self):
    """Calculates statistics of the current tasks."""
    if not self.tasks:
      return

    sorted_tasks = sorted(self.tasks, key=itemgetter('run_time'))
    self.min = sorted_tasks[0]['run_time']
    self.max = sorted_tasks[len(sorted_tasks) - 1]['run_time']
    self.mean = sorted_tasks[len(sorted_tasks) // 2]['run_time']

    # Remove the microseconds to keep things cleaner
    self.min = self.min - timedelta(microseconds=self.min.microseconds)
    self.max = self.max - timedelta(microseconds=self.max.microseconds)
    self.mean = self.mean - timedelta(microseconds=self.mean.microseconds)

  def format_stats(self):
    """Formats statistics data.

    Returns:
      String of statistics data
    """
    return '{0:s}: Count: {1:d}, Min: {2!s}, Mean: {3!s}, Max: {4!s}'.format(
        self.description, self.count, self.min, self.mean, self.max)

  def format_stats_csv(self):
    """Formats statistics data into CSV output.

    Returns:
      String of statistics data in CSV format
    """
    return '{0:s}, {1:d}, {2!s}, {3!s}, {4!s}'.format(
        self.description, self.count, self.min, self.mean, self.max)


class BaseTurbiniaClient:
  """Client class for Turbinia.

  Attributes:
    task_manager (TaskManager): Turbinia task manager
  """

  def __init__(self):
    config.LoadConfig()
    self.task_manager = task_manager.get_task_manager()
    self.task_manager.setup(server=False)

  def _create_default_recipe(self):
    """Creates a default Turbinia recipe."""
    default_recipe = recipe_helpers.DEFAULT_RECIPE
    return default_recipe

  def create_recipe(
      self, debug_tasks=False, filter_patterns=None, group_id='',
      jobs_allowlist=None, jobs_denylist=None, recipe_name=None, sketch_id=None,
      skip_recipe_validation=False, yara_rules=None, group_name=None,
      reason=None):
    """Creates a Turbinia recipe.

    If no recipe_name is specified, this  method returns a default recipe.
    If a recipe_name is specified then this method will build the recipe
    dictionary by reading the  contents of a recipe file. The path to
    the recipe file is inferred from the recipe_name and the RECIPE_FILE_DIR
    configuration parameter.

    Args:
      debug_tasks (bool): flag to turn debug output on for supported tasks.
      filter_patterns (list): a list of filter pattern strings.
      group_id (str): a group identifier.
      jobs_allowlist (list): a list of jobs allowed for execution.
      jobs_denylist (list): a list of jobs that will not be executed.
      recipe_name (str): Turbinia recipe name (e.g. triage-linux).
      sketch_id (str): a Timesketch sketch identifier.
      skip_recipe_validation (bool): flag indicates if the recipe will be
          validated.
      yara_rules (str): a string containing yara rules.
      group_name (str): Name for grouping evidence.
      reason (str): Reason or justification for Turbinia requests.

    Returns:
      dict: a Turbinia recipe dictionary.
    """
    recipe = None
    if jobs_allowlist and jobs_denylist:
      raise TurbiniaException(
          'jobs_allowlist and jobs_denylist are mutually exclusive.')

    if not recipe_name:
      # if no recipe_name is given, create a default recipe.
      recipe = self._create_default_recipe()
      if filter_patterns:
        recipe['globals']['filter_patterns'] = filter_patterns
      if jobs_denylist:
        recipe['globals']['jobs_denylist'] = jobs_denylist
      if jobs_allowlist:
        recipe['globals']['jobs_allowlist'] = jobs_allowlist
    else:
      # Load custom recipe from given path or name.
      if (jobs_denylist or jobs_allowlist or filter_patterns):
        msg = (
            'Specifying a recipe name is incompatible with defining '
            'jobs allow/deny lists, or a patterns file separately.')
        raise TurbiniaException(msg)

      if os.path.exists(recipe_name):
        recipe_path = recipe_name
      else:
        recipe_path = recipe_helpers.get_recipe_path_from_name(recipe_name)

      if not os.path.exists(recipe_path):
        msg = f'Could not find recipe file at {recipe_path:s}'
        log.error(msg)
        raise TurbiniaException(msg)

      recipe = recipe_helpers.load_recipe_from_file(
          recipe_path, skip_recipe_validation)
      if not recipe:
        msg = f'Could not load recipe from file at {recipe_path:s}.'
        raise TurbiniaException(msg)

    # Set any additional recipe parameters, if specified.
    if sketch_id:
      recipe['globals']['sketch_id'] = sketch_id
    if debug_tasks:
      recipe['globals']['debug_tasks'] = debug_tasks
    if group_id:
      recipe['globals']['group_id'] = group_id
    if group_name:
      recipe['globals']['group_name'] = group_name
    if reason:
      recipe['globals']['reason'] = reason
    if yara_rules:
      recipe['globals']['yara_rules'] = yara_rules

    return recipe

  def create_request(
      self, request_id=None, group_id=None, requester=None, recipe=None,
      evidence_=None, group_name=None, reason=None):
    """Wrapper method to create a Turbinia request."""
    default_recipe = self.create_recipe()
    request = TurbiniaRequest(
        request_id=request_id, group_id=group_id, requester=requester,
        recipe=recipe if recipe else default_recipe, evidence=evidence_,
        group_name=group_name, reason=reason)
    return request

  def list_jobs(self):
    """List the available jobs."""
    # TODO(aarontp): Refactor this out so that we don't need to depend on
    # the task manager from the client.
    log.info('Available Jobs:')
    for job in self.task_manager.jobs:
      log.info(f'\t{job.NAME:s}')

  def wait_for_request(
      self, instance, project, region, request_id=None, user=None,
      poll_interval=60):
    """Polls and waits for Turbinia Request to complete.

    Args:
      instance (string): The Turbinia instance name (by default the same as the
          INSTANCE_ID in the config).
      project (string): The name of the project.
      region (string): The name of the region to execute in.
      request_id (string): The Id of the request we want tasks for.
      user (string): The user of the request we want tasks for.
      poll_interval (int): Interval of seconds between polling cycles.
    """
    last_completed_count = -1
    last_uncompleted_count = -1
    while True:
      task_results = self.get_task_data(
          instance, project, region, request_id=request_id, user=user)
      completed_tasks = []
      uncompleted_tasks = []
      for task in task_results:
        if task.get('successful') is not None:
          completed_tasks.append(task)
        else:
          uncompleted_tasks.append(task)

      if completed_tasks and len(completed_tasks) == len(task_results):
        break

      tasks = {}
      completed_names = ''
      completed_names_list = []
      for task in completed_tasks:
        task_name = task.get('name')
        tasks[task_name] = tasks.get(task_name, 0) + 1
      for task, count in sorted(tasks.items()):
        completed_names_list.append(f'{task:s}:{count:d}')
      completed_names = ', '.join(completed_names_list)

      tasks = {}
      uncompleted_names = ''
      uncompleted_names_list = []
      for task in uncompleted_tasks:
        task_name = task.get('name')
        tasks[task_name] = tasks.get(task_name, 0) + 1
      for task, count in sorted(tasks.items()):
        uncompleted_names_list.append(f'{task:s}:{count:d}')
      uncompleted_names = ', '.join(uncompleted_names_list)

      total_count = len(completed_tasks) + len(uncompleted_tasks)
      msg = (
          'Tasks completed ({0:d}/{1:d}): [{2:s}], waiting for [{3:s}].'.format(
              len(completed_tasks), total_count, completed_names,
              uncompleted_names))
      if (len(completed_tasks) > last_completed_count or
          len(uncompleted_tasks) > last_uncompleted_count):
        log.info(msg)
      else:
        log.debug(msg)

      last_completed_count = len(completed_tasks)
      last_uncompleted_count = len(uncompleted_tasks)
      time.sleep(poll_interval)

    log.info(f'All {len(task_results):d} Tasks completed')

  def format_task_detail(self, task, show_files=False):
    """Formats a single task in detail.

    Args:
      task (dict): The task to format data for
      show_files (bool): Whether we want to print out log file paths

    Returns:
      list: Formatted task data
    """
    report = []
    saved_paths = task.get('saved_paths') or []
    status = task.get('status') or 'No task status'

    report.append(fmt.heading2(task.get('name')))
    line = f"{fmt.bold('Evidence:'):s} {task.get('evidence_name')!s}"
    report.append(fmt.bullet(line))
    line = f"{fmt.bold('Status:'):s} {status:s}"
    report.append(fmt.bullet(line))
    report.append(fmt.bullet(f"Task Id: {task.get('id')!s}"))
    report.append(fmt.bullet(f"Executed on worker {task.get('worker_name')!s}"))
    if task.get('report_data'):
      report.append('')
      report.append(fmt.heading3('Task Reported Data'))
      report.extend(task.get('report_data').splitlines())
    if show_files:
      report.append('')
      report.append(fmt.heading3('Saved Task Files:'))
      for path in saved_paths:
        report.append(fmt.bullet(fmt.code(path)))
      report.append('')
    return report

  def format_worker_task(self, task):
    """Formats a single task for Worker view.

    Args:
      task (dict): The task to format data for
    Returns:
      list: Formatted task data
    """
    report = []
    report.append(fmt.bullet(f"{task['task_id']:s} - {task['task_name']:s}"))
    report.append(
        fmt.bullet(
            f"Last Update: {task['last_update'].strftime(DATETIME_FORMAT):s}",
            level=2))
    report.append(fmt.bullet(f"Status: {task['status']:s}", level=2))
    report.append(fmt.bullet(f"Run Time: {str(task['run_time']):s}", level=2))
    report.append('')
    return report

  def format_task(self, task, show_files=False):
    """Formats a single task in short form.

    Args:
      task (dict): The task to format data for
      show_files (bool): Whether we want to print out log file paths

    Returns:
      list: Formatted task data
    """
    report = []
    saved_paths = task.get('saved_paths') or []
    status = task.get('status') or 'No task status'
    report.append(
        fmt.bullet(
            f"{task.get('name'):s} ({task.get('evidence_name')!s}): {status:s}")
    )
    if show_files:
      for path in saved_paths:
        report.append(fmt.bullet(fmt.code(path), level=2))
      report.append('')
    return report

  def get_task_statistics(
      self, instance, project, region, days=0, task_id=None, request_id=None,
      user=None):
    """Gathers statistics for Turbinia execution data.

    Args:
      instance (string): The Turbinia instance name (by default the same as the
          INSTANCE_ID in the config).
      project (string): The name of the project.
      region (string): The name of the zone to execute in.
      days (int): The number of days we want history for.
      task_id (string): The Id of the task.
      request_id (string): The Id of the request we want tasks for.
      user (string): The user of the request we want tasks for.

    Returns:
      task_stats(dict): Mapping of statistic names to values
    """
    task_results = self.get_task_data(
        instance, project, region, days, task_id, request_id, user)
    if not task_results:
      return {}

    task_stats = {
        'all_tasks': TurbiniaStats('All Tasks'),
        'successful_tasks': TurbiniaStats('Successful Tasks'),
        'failed_tasks': TurbiniaStats('Failed Tasks'),
        'requests': TurbiniaStats('Total Request Time'),
        # The following are dicts mapping the user/worker/type names to their
        # respective TurbiniaStats() objects.
        # Total wall-time for all tasks of a given type
        'tasks_per_type': {},
        # Total wall-time for all tasks per Worker
        'tasks_per_worker': {},
        # Total wall-time for all tasks per User
        'tasks_per_user': {},
    }

    # map of request ids to [min time, max time]
    requests = {}

    for task in task_results:
      request_id = task.get('request_id')
      task_type = task.get('name')
      worker = task.get('worker_name')
      user = task.get('requester')
      if not task.get('run_time'):
        log.debug(
            'Ignoring task {0:s} in statistics because the run_time is not '
            'set, and it is required to calculate stats'.format(
                task.get('name')))
        continue

      # Stats for all/successful/failed tasks
      task_stats['all_tasks'].add_task(task)
      if task.get('successful') is True:
        task_stats['successful_tasks'].add_task(task)
      elif task.get('successful') is False:
        task_stats['failed_tasks'].add_task(task)

      # Stats for Tasks per Task type.
      if task_type in task_stats['tasks_per_type']:
        task_type_stats = task_stats['tasks_per_type'].get(task_type)
      else:
        task_type_stats = TurbiniaStats(f'Task type {task_type:s}')
        task_stats['tasks_per_type'][task_type] = task_type_stats
      task_type_stats.add_task(task)

      # Stats per worker.
      if worker in task_stats['tasks_per_worker']:
        worker_stats = task_stats['tasks_per_worker'].get(worker)
      else:
        worker_stats = TurbiniaStats(f'Worker {worker:s}')
        task_stats['tasks_per_worker'][worker] = worker_stats
      worker_stats.add_task(task)

      # Stats per submitting User.
      if user in task_stats['tasks_per_user']:
        user_stats = task_stats['tasks_per_user'].get(user)
      else:
        user_stats = TurbiniaStats(f'User {user:s}')
        task_stats['tasks_per_user'][user] = user_stats
      user_stats.add_task(task)

      # Stats for the total request.  This will, for each request, calculate the
      # start time of the earliest task and the stop time of the latest task.
      # This will give the overall run time covering all tasks in the request.
      task_start_time = task['last_update'] - task['run_time']
      task_stop_time = task['last_update']
      if request_id in requests:
        start_time, stop_time = requests[request_id]
        if task_start_time < start_time:
          requests[request_id][0] = task_start_time
        if task_stop_time > stop_time:
          requests[request_id][1] = task_stop_time
      else:
        requests[request_id] = [task_start_time, task_stop_time]

    # Add a fake task result for each request with our calculated times to the
    # stats module
    for min_time, max_time in requests.values():
      task = {}
      task['run_time'] = max_time - min_time
      task_stats['requests'].add_task(task)

    # Go over all stat objects and calculate them
    for stat_obj in task_stats.values():
      if isinstance(stat_obj, dict):
        for inner_stat_obj in stat_obj.values():
          inner_stat_obj.calculate_stats()
      else:
        stat_obj.calculate_stats()

    return task_stats

  def format_task_statistics(
      self, instance, project, region, days=0, task_id=None, request_id=None,
      user=None, csv=False):
    """Formats statistics for Turbinia execution data.

    Args:
      instance (string): The Turbinia instance name (by default the same as the
          INSTANCE_ID in the config).
      project (string): The name of the project.
      region (string): The name of the zone to execute in.
      days (int): The number of days we want history for.
      task_id (string): The Id of the task.
      request_id (string): The Id of the request we want tasks for.
      user (string): The user of the request we want tasks for.
      csv (bool): Whether we want the output in CSV format.

    Returns:
      String of task statistics report
    """
    task_stats = self.get_task_statistics(
        instance, project, region, days, task_id, request_id, user)
    if not task_stats:
      return 'No tasks found'

    stats_order = [
        'all_tasks', 'successful_tasks', 'failed_tasks', 'requests',
        'tasks_per_type', 'tasks_per_worker', 'tasks_per_user'
    ]

    if csv:
      report = ['stat_type, count, min, mean, max']
    else:
      report = ['Execution time statistics for Turbinia:', '']
    for stat_name in stats_order:
      stat_obj = task_stats[stat_name]
      if isinstance(stat_obj, dict):
        # Sort by description so that we get consistent report output
        inner_stat_objs = sorted(
            stat_obj.values(), key=attrgetter('description'))
        for inner_stat_obj in inner_stat_objs:
          if csv:
            report.append(inner_stat_obj.format_stats_csv())
          else:
            report.append(inner_stat_obj.format_stats())
      else:
        if csv:
          report.append(stat_obj.format_stats_csv())
        else:
          report.append(stat_obj.format_stats())

    report.append('')
    return '\n'.join(report)

  def format_worker_status(
      self, instance, project, region, days=0, all_fields=False):
    """Formats the recent history for Turbinia Workers.

    Args:
      instance (string): The Turbinia instance name (by default the same as the
          INSTANCE_ID in the config).
      project (string): The name of the project.
      region (string): The name of the zone to execute in.
      days (int): The number of days we want history for.
      all_fields (bool): Include historical Task information for the worker.
    Returns:
      String of Request status
    """
    # Set number of days to retrieve data
    num_days = 7
    if days != 0:
      num_days = days
    task_results = self.get_task_data(instance, project, region, days=num_days)
    if not task_results:
      return ''

    # Sort task_results by last updated timestamp.
    task_results = sorted(
        task_results, key=itemgetter('last_update'), reverse=True)

    # Create dictionary of worker_node: {{task_id, task_update,
    # task_name, task_status}}
    workers_dict = {}
    unassigned_dict = {}
    scheduled_counter = 0
    for result in task_results:
      worker_node = result.get('worker_name')
      status = result.get('status')
      status = status if status else 'No task status'
      if worker_node and worker_node not in workers_dict:
        workers_dict[worker_node] = []
      elif not worker_node:
        # Track scheduled/unassigned Tasks for reporting.
        scheduled_counter += 1
        worker_node = 'Unassigned'
        if worker_node not in unassigned_dict:
          unassigned_dict[worker_node] = []
      if worker_node:
        task_dict = {}
        task_dict['task_id'] = result.get('id')
        task_dict['last_update'] = result.get('last_update')
        task_dict['task_name'] = result.get('name')
        task_dict['status'] = status
        # Check status for anything that is running.
        if 'running' in status:
          run_time = (datetime.utcnow() -
                      result.get('last_update')).total_seconds()
          run_time = timedelta(seconds=run_time)
          task_dict['run_time'] = run_time
        else:
          run_time = result.get('run_time')
          task_dict['run_time'] = run_time if run_time else 'No run time.'
        # Update to correct dictionary
        if worker_node == 'Unassigned':
          unassigned_dict[worker_node].append(task_dict)
        else:
          workers_dict[worker_node].append(task_dict)

    # Generate report header
    report = []
    report.append(
        fmt.heading1(
            f'Turbinia report for Worker activity within {num_days:d} days'))
    report.append(fmt.bullet(f'{len(workers_dict.keys()):d} Worker(s) found.'))
    report.append(
        fmt.bullet(
            '{0:d} Task(s) unassigned or scheduled and pending Worker assignment.'
            .format(scheduled_counter)))
    for worker_node, tasks in workers_dict.items():
      report.append('')
      report.append(fmt.heading2(f'Worker Node: {worker_node:s}'))
      # Append the statuses chronologically
      run_status, queued_status, other_status = [], [], []
      for task in tasks:
        if 'running' in task['status']:
          run_status.extend(self.format_worker_task(task))
        elif 'queued' in task['status']:
          queued_status.extend(self.format_worker_task(task))
        else:
          other_status.extend(self.format_worker_task(task))
      # Add each of the status lists back to report list
      not_found = [fmt.bullet('No Tasks found.')]
      report.append(fmt.heading3('Running Tasks'))
      report.extend(run_status if run_status else not_found)
      report.append('')
      report.append(fmt.heading3('Queued Tasks'))
      report.extend(queued_status if queued_status else not_found)
      # Add Finished Tasks
      if all_fields:
        report.append('')
        report.append(fmt.heading3('Finished Tasks'))
        report.extend(other_status if other_status else not_found)

    # Add unassigned worker tasks
    unassigned_status = []
    for tasks in unassigned_dict.values():
      for task in tasks:
        unassigned_status.extend(self.format_worker_task(task))
    # Now add to main report
    if all_fields:
      report.append('')
      report.append(fmt.heading2('Unassigned Worker Tasks'))
      report.extend(unassigned_status if unassigned_status else not_found)

    return '\n'.join(report)

  def format_request_status(
      self, instance, project, region, days=0, all_fields=False):
    """Formats the recent history for Turbinia Requests.

    Args:
      instance (string): The Turbinia instance name (by default the same as the
          INSTANCE_ID in the config).
      project (string): The name of the project.
      region (string): The name of the zone to execute in.
      days (int): The number of days we want history for.
      all_fields (bool): Include all fields for the Request, which includes,
          saved file paths.
    Returns:
      String of Request status
    """
    # Set number of days to retrieve data
    num_days = 7
    if days != 0:
      num_days = days
    task_results = self.get_task_data(instance, project, region, days=num_days)
    if not task_results:
      return ''

    # Sort task_results by last updated timestamp.
    task_results = sorted(
        task_results, key=itemgetter('last_update'), reverse=True)

    # Create dictionary of request_id: {saved_paths, last_update, requester,
    # task_id}
    request_dict = {}
    for result in task_results:
      request_id = result.get('request_id')
      saved_paths = result.get('saved_paths')
      if request_id not in request_dict:
        saved_paths = set(saved_paths) if saved_paths else set()
        request_dict[request_id] = {}
        request_dict[request_id]['saved_paths'] = saved_paths
        request_dict[request_id]['last_update'] = result.get('last_update')
        request_dict[request_id]['requester'] = result.get('requester')
        request_dict[request_id]['task_id'] = set([result.get('id')])
      else:
        if saved_paths:
          request_dict[request_id]['saved_paths'].update(saved_paths)
        request_dict[request_id]['task_id'].update([result.get('id')])

    # Generate report header
    report = []
    report.append(
        fmt.heading1(
            f'Turbinia report for Requests made within {num_days:d} days'))
    report.append(
        fmt.bullet(
            f'{len(request_dict.keys()):d} requests were made within this timeframe.'
        ))
    # Print report data for Requests
    for request_id, values in request_dict.items():
      report.append('')
      report.append(fmt.heading2(f'Request ID: {request_id:s}'))
      report.append(
          fmt.bullet(
              f"Last Update: {values['last_update'].strftime(DATETIME_FORMAT):s}"
          ))
      report.append(fmt.bullet(f"Requester: {values['requester']:s}"))
      report.append(fmt.bullet(f"Task Count: {len(values['task_id']):d}"))
      if all_fields:
        report.append(fmt.bullet('Associated Evidence:'))
        # Append all saved paths in request
        for path in sorted(values['saved_paths']):
          report.append(fmt.bullet(fmt.code(path), level=2))
        report.append('')
    return '\n'.join(report)

  def format_task_status(
      self, instance, project, region, days=0, task_id=None, request_id=None,
      group_id=None, user=None, all_fields=False, full_report=False,
      priority_filter=Priority.HIGH, output_json=False, report=None):
    """Formats the recent history for Turbinia Tasks.

    Args:
      instance (string): The Turbinia instance name (by default the same as the
          INSTANCE_ID in the config).
      project (string): The name of the project.
      region (string): The name of the zone to execute in.
      days (int): The number of days we want history for.
      task_id (string): The Id of the task.
      request_id (string): The Id of the request we want tasks for.
      group_id (string): Group Id of the requests.
      user (string): The user of the request we want tasks for.
      all_fields (bool): Include all fields for the task, including task,
          request ids and saved file paths.
      full_report (bool): Generate a full markdown report instead of just a
          summary.
      priority_filter (int): Output only a summary for Tasks with a value
          greater than the priority_filter.
      output_json (bool): Whether to return JSON output.
      report (string): Status report that will be returned.

    Returns:
      String of task status in JSON or human readable format.
    """
    if user and days == 0:
      days = 1000
    task_results = self.get_task_data(
        instance, project, region, days, task_id, request_id, group_id, user,
        output_json=output_json)
    if not task_results:
      return ''

    if output_json:
      return task_results

    # Sort all tasks by the report_priority so that tasks with a higher
    # priority are listed first in the report.
    for result in task_results:
      # 0 is a valid value, so checking against specific values
      if result.get('report_priority') in (None, ''):
        result['report_priority'] = Priority.LOW
    task_results = sorted(task_results, key=itemgetter('report_priority'))
    num_results = len(task_results)
    if not num_results:
      msg = 'No Turbinia Tasks found.'
      log.info(msg)
      return f'\n{msg:s}'

    # Build up data
    if report is None:
      report = []
    success_types = ['Successful', 'Failed', 'Scheduled or Running']
    success_values = [True, False, None]
    # Reverse mapping values to types
    success_map = dict(zip(success_values, success_types))
    # This is used for group ID status
    requests = defaultdict(dict)
    requester = task_results[0].get('requester')
    request_id = task_results[0].get('request_id')
    task_map = defaultdict(list)
    success_types.insert(0, 'High Priority')
    for task in task_results:
      if task.get('request_id') not in requests:
        requests[task.get('request_id')] = {
            'Successful': 0,
            'Failed': 0,
            'Scheduled or Running': 0
        }
      requests[task.get('request_id')][success_map[task.get('successful')]] += 1
      if task.get('report_priority') <= priority_filter:
        task_map['High Priority'].append(task)
      else:
        task_map[success_map[task.get('successful')]].append(task)

    if group_id:
      report.append('\n')
      report.append(fmt.heading1(f'Turbinia report for group ID {group_id:s}'))
      for request_id, success_counts in requests.items():
        report.append(
            fmt.bullet(
                'Request Id {0:s} with {1:d} successful, {2:d} failed, and {3:d} running tasks.'
                .format(
                    request_id, success_counts['Successful'],
                    success_counts['Failed'],
                    success_counts['Scheduled or Running'])))
        if full_report:
          self.format_task_status(
              instance, project, region, days=0, task_id=None,
              request_id=request_id, user=user, all_fields=all_fields,
              full_report=full_report, priority_filter=priority_filter,
              output_json=output_json, report=report)

      return '\n'.join(report)

    # Generate report header
    report.append('\n')
    report.append(fmt.heading1(f'Turbinia report {request_id:s}'))
    report.append(
        fmt.bullet(f'Processed {num_results:d} Tasks for user {requester:s}'))

    # Print report data for tasks
    for success_type in success_types:
      report.append('')
      report.append(fmt.heading1(f'{success_type:s} Tasks'))
      if not task_map[success_type]:
        report.append(fmt.bullet('None'))
      task_counter = defaultdict(int)
      for task in task_map[success_type]:
        if full_report and success_type == success_types[0]:
          report.extend(self.format_task_detail(task, show_files=all_fields))
        elif success_type == success_types[2]:
          report.extend(self.format_task(task, show_files=all_fields))
        else:
          task_counter['\n'.join(self.format_task(task,
                                                  show_files=all_fields))] += 1

      if len(task_counter):
        for k, v in task_counter.items():
          if v == 1:
            report.append(k)
          else:
            report.append(f'{k:s} x {v:d}')

    return '\n'.join(report)

  def send_request(self, request):
    """Sends a TurbiniaRequest message.

    Args:
      request: A TurbiniaRequest object.
    """
    pass


class TurbiniaCeleryClient(BaseTurbiniaClient):
  """Client class for Turbinia (Celery).

  Overriding some things specific to Celery operation.

  Attributes:
    redis (RedisStateManager): Redis datastore object
  """

  def __init__(self, *args, **kwargs):
    super(TurbiniaCeleryClient, self).__init__(*args, **kwargs)
    self.redis = RedisStateManager()

  # pylint: disable=arguments-differ
  def close_tasks(
      self, instance, request_id=None, group_id=None, task_id=None,
      user=None) -> bool:
    """Close Turbinia Tasks based on Request ID.

    This method uses Celery app.control.terminate to terminate and revoke a
    task_id or a list of task_ids. If a task is revoked, the workers will
    ignore the task and not execute it after all.

    Args:
      instance (string): The Turbinia instance name (by default the same as the
          INSTANCE_ID in the config).
      request_id (string): The request identifier we want tasks for.
      task_id (string): The task identifier we want.
      group_id (str): A group identifier we want tasks for.
      user (string): The user of the request we want tasks for.

    Returns: True if a terminate command was successfully broadcast to the
        Celery workers.
    """
    tasks = self.redis.get_task_data(
        instance, task_id=task_id, request_id=request_id, group_id=group_id,
        user=user)
    task_ids = [task.get('id') for task in tasks if task.get('id')]
    result = False

    if task_ids:
      for _task_id in task_ids:
        self.task_manager.celery.app.control.terminate(_task_id)
        log.info(f'Closed task {_task_id}.')
        task_dict = self.redis.get_task_data(
            instance=config.INSTANCE_ID, task_id=_task_id)[0]
        task = TurbiniaTask().deserialize(task_dict)
        task['success'] = False
        task['status'] = 'Task forcefully closed.'
        self.redis.update_task(task)
      result = True
    else:
      log.info('No tasks found with the given filter(s). Not closing any tasks')
    return bool(result)

  def send_request(self, request):
    """Sends a TurbiniaRequest message.

    Args:
      request: A TurbiniaRequest object.
    """
    self.task_manager.kombu.send_request(request)

  # pylint: disable=arguments-differ
  def get_task_data(
      self, instance, _, __, days=0, task_id=None, request_id=None,
      group_id=None, user=None, function_name=None, output_json=False):
    """Gets task data from Redis.

    We keep the same function signature, but ignore arguments passed for GCP.

    Args:
      instance (string): The Turbinia instance name (by default the same as the
          INSTANCE_ID in the config).
      days (int): The number of days we want history for.
      task_id (string): The Id of the task.
      request_id (string): The Id of the request we want tasks for.
      group_id (string): Group Id of the requests.
      user (string): The user of the request we want tasks for.
      function_name (string): unused.
      output_json (bool): unused.

    Returns:
      List of Task dict objects.
    """
    return self.redis.get_task_data(
        instance, days, task_id, request_id, group_id, user)
