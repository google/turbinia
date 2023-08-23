#!/usr/bin/env python
#
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
"""Methods for formatting text."""

from __future__ import annotations

from abc import ABC, abstractmethod
from click import echo as click_echo

import logging
import json
import pandas

log = logging.getLogger('turbinia')


def echo_json(json_data: dict) -> None:
  """Pretty print JSON data."""
  if isinstance(json_data, dict):
    click_echo(json.dumps(json_data, indent=2))


class MarkdownReportComponent(ABC):
  """Components for generating Turbinia request/task
      markdown reports.
  """

  def __init__(self):
    """Instantiates a MarkdownReportComponent object."""
    self._components: list(MarkdownReportComponent) = []
    self._parent: MarkdownReportComponent = None
    self._report: str = None

  @property
  def components(self):
    """Returns the components list."""
    return self._components

  @property
  def report(self):
    """Returns the markdown report text."""
    return self._report

  @report.setter
  def report(self, report):
    self._report = report

  @property
  def parent(self) -> MarkdownReportComponent:
    """Returns the parent object."""
    return self._parent

  @parent.setter
  def parent(self, parent: MarkdownReportComponent):
    self._parent = parent

  def bold(self, text):
    """Formats text as bold in Markdown format.

    Args:
        text(string): Text to format

    Return:
        string: Formatted text.
    """
    return f'**{text.strip():s}**'

  def heading1(self, text):
    """Formats text as heading 1 in Markdown format.

    Args:
        text(string): Text to format

    Return:
        string: Formatted text.
    """
    return f'# {text.strip():s}'

  def heading2(self, text):
    """Formats text as heading 2 in Markdown format.

    Args:
        text(string): Text to format

    Return:
        string: Formatted text.
    """
    return f'## {text.strip():s}'

  def heading3(self, text):
    """Formats text as heading 3 in Markdown format.

    Args:
        text(string): Text to format

    Return:
        string: Formatted text.
    """
    return f'### {text.strip():s}'

  def heading4(self, text):
    """Formats text as heading 4 in Markdown format.

    Args:
        text(string): Text to format

    Return:
        string: Formatted text.
    """
    return f'#### {text.strip():s}'

  def heading5(self, text):
    """Formats text as heading 5 in Markdown format.
     Args:
        text(string): Text to format
     Return:
        string: Formatted text.
    """
    return f'##### {text.strip():s}'

  def bullet(self, text, level=1):
    """Formats text as a bullet in Markdown format.

      Args:
        text(string): Text to format
        level(int): Indentation level.
      Return:
        string: Formatted text.
    """
    return f"{'    ' * (level - 1):s}* {text.strip():s}"

  def code(self, text):
    """Formats text as code in Markdown format.

      Args:
          text(string): Text to format

     Return:
          string: Formatted text.
    """
    return f'`{text.strip():s}`'

  def add(self, component: MarkdownReportComponent) -> None:
    """Adds a MarkdownReportComponent object to the components list.

    This method should additionally set the parent object.
    """
    pass

  def add_components(self, components: list[MarkdownReportComponent]) -> None:
    """Adds multiple MarkdownReportComponent objects to the components list."""
    pass

  def remove(self, component: MarkdownReportComponent) -> None:
    """Removes a MarkdownReportComponent object from the components list.

    This method should set the component's object to None.
    """
    pass

  @abstractmethod
  def generate_markdown(self) -> str:
    pass


class TaskMarkdownReport(MarkdownReportComponent):
  """Turbinia Task markdown report."""

  def __init__(self, request_data: dict = None):
    """Initialize TaskMarkdownReport"""
    super().__init__()
    self._request_data: dict = request_data

  def generate_markdown(self) -> str:
    """Generate a markdown report."""
    report: list[str] = []
    task: dict = self._request_data
    if not task:
      return ''

    try:
      report.append(self.heading2(task.get('name')))
      line = f"{self.bold('Evidence:'):s} {task.get('evidence_name')!s}"
      report.append(self.bullet(line))
      line = f"{self.bold('Status:'):s} {task.get('status')!s}"
      report.append(self.bullet(line))
      report.append(self.bullet(f"Task Id: {task.get('id')!s}"))
      report.append(
          self.bullet(f"Executed on worker {task.get('worker_name')!s}"))
      if task.get('report_data'):
        report.append('')
        report.append(self.heading3('Task Reported Data'))
        report.extend(task.get('report_data').splitlines())
      report.append('')
      report.append(self.heading3('Saved Task Files:'))

      saved_paths = task.get('saved_paths')
      if saved_paths:
        for path in saved_paths:
          report.append(self.bullet(self.code(path)))
          report.append('')
    except TypeError as exception:
      log.warning(f'Error formatting the Markdown report: {exception!s}')

    self.report = '\n'.join(report)
    return self.report


class RequestMarkdownReport(MarkdownReportComponent):
  """Turbinia Request Markdown report."""

  def __init__(self, request_data: dict):
    """Initializes a RequestMarkdownReport object."""
    super().__init__()
    self._request_data: dict = request_data

    tasks = [TaskMarkdownReport(task) for task in request_data.get('tasks')]
    self.add_components(tasks)

  def add(self, component: MarkdownReportComponent) -> None:
    if component:
      self.components.append(component)
      component.parent = self

  def remove(self, component: MarkdownReportComponent) -> None:
    self.components.remove(component)
    component.parent = None

  def add_components(self, components: list[MarkdownReportComponent]) -> None:
    if components:
      for component in components:
        self.components.append(component)
        component.parent = self

  def generate_markdown(self) -> str:
    """Generates a Markdown version of Requests results."""
    report: list[str] = []
    request_dict: dict = self._request_data
    if not request_dict:
      return ''

    try:
      report.append(
          self.heading2(f"Request ID: {request_dict.get('request_id')}"))
      report.append(
          self.bullet(
              f"Last Update: {request_dict.get('last_task_update_time')}"))
      report.append(self.bullet(f"Requester: {request_dict.get('requester')}"))
      report.append(self.bullet(f"Reason: {request_dict.get('reason')}"))
      report.append(self.bullet(f"Status: {request_dict.get('status')}"))
      report.append(
          self.bullet(f"Failed tasks: {request_dict.get('failed_tasks')}"))
      report.append(
          self.bullet(f"Running tasks: {request_dict.get('running_tasks')}"))
      report.append(
          self.bullet(
              f"Successful tasks: {request_dict.get('successful_tasks')}"))
      report.append(
          self.bullet(f"Task Count: {request_dict.get('task_count')}"))
      report.append(
          self.bullet(f"Queued tasks: {request_dict.get('queued_tasks')}"))
      report.append(
          self.bullet(f"Evidence Name: {request_dict.get('evidence_name')}"))
      report.append('')
    except TypeError as exception:
      log.warning(f'Error formatting the Markdown report: {exception!s}')

    for task in self.components:
      report.append(task.generate_markdown())

    self.report = '\n'.join(report)
    return self.report


class SummaryMarkdownReport(MarkdownReportComponent):
  """A markdown report summary of all Turbinia Requests."""

  def __init__(self, requests_summary: list[dict]):
    """Initialize SummaryMarkdownReport."""
    super().__init__()
    self._requests_summary = requests_summary

  def generate_markdown(self) -> str:
    """Generate a Markdown version of Requests summary results."""
    report: list[str] = []
    requests_status_list = None
    if self._requests_summary:
      requests_status_list = self._requests_summary.get('requests_status')

    if not requests_status_list:
      return '## No requests found.'

    for request_dict in requests_status_list:
      request_report = RequestMarkdownReport(request_dict).generate_markdown()
      report.append(request_report)

    self.report = '\n'.join(report)
    return self.report


class WorkersMarkdownReport(MarkdownReportComponent):
  """A markdown report of all tasks for a specific worker."""

  def __init__(self, workers_status: dict, days: int):
    super().__init__()
    self._workers_status: dict = workers_status
    self._days: int = days

  def generate_markdown(self) -> str:
    """Generates a Markdown version of tasks per worker.
    
    Returns:
      markdown (str): Markdown version of tasks per worker.
    """
    report = []
    worker_status = self._workers_status.copy()
    scheduled_tasks = worker_status.pop('scheduled_tasks')
    report.append(
        self.heading1(
            f'Turbinia report for Worker activity within {self._days} days'))
    report.append(self.bullet(f'{len(worker_status.keys())} Worker(s) found.'))
    report.append(
        self.bullet(
            f'{scheduled_tasks} Task(s) unassigned or scheduled and pending '
            f'Worker assignment.'))
    for worker_node, task_types in worker_status.items():
      report.append('')
      report.append(self.heading2(f'Worker Node: {worker_node:s}'))
      for task_type, tasks in task_types.items():
        report.append(self.heading3(task_type.replace('_', ' ').title()))
        if not tasks:
          report.append(self.bullet('No Tasks found.'))
          report.append('')
          continue
        for task_id, task_attributes in tasks.items():
          report.append(
              self.bullet(f'{task_id} - {task_attributes["task_name"]}'))
          for attribute_name, attribute_value in task_attributes.items():
            if attribute_name != 'task_name':
              formatted_name = attribute_name.replace('_', ' ').title()
              report.append(
                  self.bullet(f'{formatted_name}: {attribute_value}', level=2))
        report.append('')

    return '\n'.join(report)


class StatsMarkdownReport(MarkdownReportComponent):
  """A markdown report of the task statistics."""

  def __init__(self, statistics: dict):
    super().__init__()
    self._statistics: dict = statistics
    self.table_dict = {
        'TASK': [],
        'COUNT': [],
        'MIN': [],
        'MEAN': [],
        'MAX': []
    }

  def stat_to_row(self, task: str, stat_dict: dict):
    """Generates a row of the statistics table.
    
    Args:
      task (str): Name of the current task.
      stat_dict (dict): Dictionary with information about current row.
    """
    self.table_dict['TASK'].append(f'{task}')
    self.table_dict['COUNT'].append(stat_dict.get('count', ''))
    self.table_dict['MIN'].append(stat_dict.get('min', ''))
    self.table_dict['MEAN'].append(stat_dict.get('mean', ''))
    self.table_dict['MAX'].append(stat_dict.get('max', ''))

  def generate_data_frame(self, markdown: bool = False) -> pandas.DataFrame:
    """Generates a pandas DataFrame of the statistics table

    Args:
      markdown (bool): Bool defining if the tasks should be in markdown format.
    
    Returns: 
      data_frame (DataFrame): Statistics table in pandas DataFrame format.
    """
    for stat_group, stat_dict in self._statistics.items():
      stat_group = stat_group.replace('_', ' ').title()
      if stat_group in ('All Tasks', 'Successful Tasks', 'Failed Tasks',
                        'Requests'):
        first_column = self.heading2(
            f'{stat_group}:') if markdown else stat_group
        self.stat_to_row(first_column, stat_dict)
        continue
      if markdown:
        self.stat_to_row(self.heading2(f'{stat_group}:'), {})
      for description, inner_dict in stat_dict.items():
        first_column = self.bullet(
            f'{description}:'
        ) if markdown else f'{stat_group.split(" ")[-1]} {description}'
        self.stat_to_row(first_column, inner_dict)

    return pandas.DataFrame(self.table_dict)

  def ljust(self, s):
    """Left justifies cells in data_frame."""
    s = s.astype(str).str.strip()
    return s.str.ljust(s.str.len().max())

  def generate_markdown(self) -> str:
    """Generates a Markdown version of task statistics.
    
    Returns:
      markdown(str): Markdown version of task statistics.
    """
    report = [self.heading1('Execution time statistics for Turbinia:')]

    data_frame = self.generate_data_frame(True)

    table = data_frame.apply(self.ljust).to_string(
        index=False, justify='left', col_space=8)

    report.append(self.heading2(table))

    return '\n'.join(report)

  def generate_csv(self) -> str:
    """Generates a CSV version of task statistics.
    
    Returns:
      csv(str): CSV version of task statistics.
    """
    return self.generate_data_frame().to_csv(index=False)
