# -*- coding: utf-8 -*-
# Copyright 2022 Google Inc.
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
"""Turbinia API server Request models."""

import logging

from operator import attrgetter
from pydantic import BaseModel

from turbinia import client
from turbinia import state_manager
from turbinia import config as turbinia_config

log = logging.getLogger('turbinia:api_server:routes:request')


class TasksStatistics(BaseModel):
  """Statistics about classes."""
  all_tasks: dict = {}
  successful_tasks: dict = {}
  failed_tasks: dict = {}
  requests: dict = {}
  tasks_per_type: dict = {}
  tasks_per_worker: dict = {}
  tasks_per_user: dict = {}

  def get_statistics(
      self, instance: str, days: int = 0, task_id: str = None,
      request_id: str = None, user: str = None) -> dict:
    """Gathers statistics for Turbinia execution data.

      Args:
        instance (string): The Turbinia instance name (by default the same as the
            INSTANCE_ID in the config).
        days (int): The number of days we want history for.
        task_id (string): The Id of the task.
        request_id (string): The Id of the request we want tasks for.
        user (string): The user of the request we want tasks for.

      Returns:
        task_stats(dict): Mapping of statistic names to values
      """
    task_results = state_manager.get_state_manager().get_task_data(
        instance, days, task_id, request_id, user)

    if not task_results:
      return {}

    task_stats = {
        'all_tasks': client.TurbiniaStats('All Tasks'),
        'successful_tasks': client.TurbiniaStats('Successful Tasks'),
        'failed_tasks': client.TurbiniaStats('Failed Tasks'),
        'requests': client.TurbiniaStats('Total Request Time'),
        # The following are dicts mapping the user/worker/type names to their
        # respective client.TurbiniaStats() objects.
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
        task_type_stats = client.TurbiniaStats(f'Task type {task_type:s}')
        task_stats['tasks_per_type'][task_type] = task_type_stats
      task_type_stats.add_task(task)

      # Stats per worker.
      if worker in task_stats['tasks_per_worker']:
        worker_stats = task_stats['tasks_per_worker'].get(worker)
      else:
        worker_stats = client.TurbiniaStats(f'Worker {worker:s}')
        task_stats['tasks_per_worker'][worker] = worker_stats
      worker_stats.add_task(task)

      # Stats per submitting User.
      if user in task_stats['tasks_per_user']:
        user_stats = task_stats['tasks_per_user'].get(user)
      else:
        user_stats = client.TurbiniaStats(f'User {user:s}')
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
      self, days: int = 0, task_id: str = None, request_id: str = None,
      user: str = None) -> bool:
    """Formats statistics for Turbinia execution data as a json-serializable dict.

      Args:
        days (int): The number of days we want history for.
        task_id (string): The Id of the task.
        request_id (string): The Id of the request we want tasks for.
        user (string): The user of the request we want tasks for.

      Returns:
        report (dict): Task statistics report.
      """
    task_stats = self.get_statistics(
        turbinia_config.INSTANCE_ID, days, task_id, request_id, user)

    report = {}
    if not task_stats:
      return report

    stats_order = [
        'all_tasks', 'successful_tasks', 'failed_tasks', 'requests',
        'tasks_per_type', 'tasks_per_worker', 'tasks_per_user'
    ]
    self.tasks_per_worker, self.tasks_per_user, self.tasks_per_type = {}, {}, {}
    for stat_name in stats_order:
      stat_obj = task_stats[stat_name]
      if isinstance(stat_obj, dict):
        # Sort by description so that we get consistent report output
        inner_stat_objs = sorted(
            stat_obj.values(), key=attrgetter('description'))
        for inner_stat_obj in inner_stat_objs:
          if stat_name == 'tasks_per_worker':
            description = inner_stat_obj.description.replace('Worker ', '', 1)
            self.tasks_per_worker[description] = inner_stat_obj.to_dict()
          elif stat_name == 'tasks_per_user':
            description = inner_stat_obj.description.replace('User ', '', 1)
            self.tasks_per_user[description] = inner_stat_obj.to_dict()
          else:
            description = inner_stat_obj.description.replace(
                'Task type ', '', 1)
            self.tasks_per_type[description] = inner_stat_obj.to_dict()
        continue
      elif stat_name == 'all_tasks':
        self.all_tasks = stat_obj.to_dict()
      elif stat_name == 'successful_tasks':
        self.successful_tasks = stat_obj.to_dict()
      elif stat_name == 'failed_tasks':
        self.failed_tasks = stat_obj.to_dict()
      elif stat_name == 'requests':
        self.requests = stat_obj.to_dict()
    return bool(self.all_tasks)
