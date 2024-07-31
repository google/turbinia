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
from httpx import Response
from typing import Any
from collections import defaultdict

import logging
import json
import pandas

MEDIUM_PRIORITY = 50
HIGH_PRIORITY = 20
CRITICAL_PRIORITY = 10

log = logging.getLogger(__name__)

IMPORTANT_ATTRIBUTES = {
    'id', '_name', 'type', 'size', 'request_id', 'tasks', 'source_path',
    'local_path', 'creation_time', 'last_update'
}


def echo_json(data: Any) -> None:
  """Pretty print JSON data."""
  try:
    if isinstance(data, str):
      json_string: str = json.loads(data)
      json_string = json.dumps(json_string, indent=2)
    else:
      json_string: str = json.dumps(data, indent=2)
    click_echo(json_string)
  except json.JSONDecodeError as exception:
    raise RuntimeError('Unable to decode API response') from exception


def decode_api_response(data: Any) -> str:
  """Decodes ApiResponse data into a Python object"""
  if isinstance(data, str) or isinstance(data, Response):
    return data

  data_attribute = None
  response = ''
  try:
    if data_attribute := getattr(data, 'data'):
      response = data_attribute
    if not data_attribute:
      if data_attribute := getattr(data, 'raw_data'):
        response = json.loads(data_attribute)
    return response
  except json.JSONDecodeError as exception:
    raise RuntimeError('Unable to decode API response') from exception
  except AttributeError as exception:
    raise RuntimeError('Unable to decode API response') from exception


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

  def heading(self, text: str, number: int) -> str:
    """Formats text as heading in Markdown format.

    Args:
        text(string): Text to format
        number(int): Heading number

    Return:
        string: Formatted text.
    """
    return f'{"#"*number} {text.strip():s}'

  def heading1(self, text):
    """Formats text as heading 1 in Markdown format.

    Args:
        text(string): Text to format

    Return:
        string: Formatted text.
    """
    return self.heading(text, 1)

  def heading2(self, text):
    """Formats text as heading 2 in Markdown format.

    Args:
        text(string): Text to format

    Return:
        string: Formatted text.
    """
    return self.heading(text, 2)

  def heading3(self, text):
    """Formats text as heading 3 in Markdown format.

    Args:
        text(string): Text to format

    Return:
        string: Formatted text.
    """
    return self.heading(text, 3)

  def heading4(self, text):
    """Formats text as heading 4 in Markdown format.

    Args:
        text(string): Text to format

    Return:
        string: Formatted text.
    """
    return self.heading(text, 4)

  def heading5(self, text):
    """Formats text as heading 5 in Markdown format.
     Args:
        text(string): Text to format
     Return:
        string: Formatted text.
    """
    return self.heading(text, 5)

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

  def list_to_markdown(self, original_list: list, level: int = 1) -> list:
    """Generates a Markdown based on a python list.

      Args:
        original_list(list): List to format
        level(int): Indentation level.

      Returns:
        report (list): List of Markdown lines.
    """
    if not original_list:
      return [self.bullet('[EMPTY LIST]', level)]
    report = []
    for item in original_list:
      if isinstance(item, dict):
        report.extend(self.dict_to_markdown(item, level + 1))
      elif isinstance(item, list):
        report.extend(self.list_to_markdown(item, level + 1))
      else:
        if level == 0:
          report.append(self.heading1(item))
        else:
          report.append(self.bullet(item, level))
    return report

  def dict_to_markdown(
      self, original_dict: dict, level: int = 1, excluded_keys: list = (),
      format_keys: bool = True) -> list:
    """Generates a Markdown based on a python dictionary.

      Args:
        original_dict(dict): Dict to format.
        level(int): Indentation level.
        excluded_keys (list): List of dict keys to be ignored.
        format_keys (bool): Capitalizes and removes underscores from dict keys
          if True

      Returns:
        report (list): List of Markdown lines.
    """
    if not original_dict:
      return [self.bullet('[EMPTY DICTIONARY]', level)]
    report: list[str] = []
    for key, value in original_dict.items():
      if key in excluded_keys:
        continue
      name = key.replace('_', ' ').title() if format_keys else key
      if isinstance(value, dict):
        if level == 0:
          report.append(self.heading1(f'{name}:'))
        else:
          report.append(self.bullet(f'{name}:', level))
        report.extend(self.dict_to_markdown(value, level + 1))
      elif isinstance(value, list):
        if level == 0:
          report.append(self.heading1(f'{name}:'))
        else:
          report.append(self.bullet(f'{name}:', level))
        report.extend(self.list_to_markdown(value, level + 1))
      else:
        if level == 0:
          report.append(self.heading1(f'{name}: {value}'))
        else:
          report.append(self.bullet(f'{name}: {value}', level))
    return report

  @abstractmethod
  def generate_markdown(self) -> str:
    pass


class TaskMarkdownReport(MarkdownReportComponent):
  """Turbinia Task markdown report."""

  def __init__(self, request_data: dict = None):
    """Initialize TaskMarkdownReport"""
    super().__init__()
    self._request_data: dict = request_data

  def generate_markdown(
      self, priority_filter=None, show_all=False, compact=False) -> str:
    """Generate a markdown report."""
    report: list[str] = []
    task: dict = self._request_data
    if not task:
      return ''

    priority = task.get('report_priority') if task.get(
        'report_priority') else MEDIUM_PRIORITY
    priority_filter = priority_filter if priority_filter else HIGH_PRIORITY

    if priority <= CRITICAL_PRIORITY:
      name = f'{task.get("name")} ({"CRITICAL PRIORITY"})'
    elif priority <= HIGH_PRIORITY:
      name = f'{task.get("name")} ({"HIGH PRIORITY"})'
    elif priority <= MEDIUM_PRIORITY:
      name = f'{task.get("name")} ({"MEDIUM PRIORITY"})'
    else:
      name = f'{task.get("name")} ({"LOW PRIORITY"})'

    try:
      # Only show Task details if the Task has more priority than the
      # priority_filter
      if priority > priority_filter:
        report.append(f'{self.heading3(name)}: {task.get("status")!s}')
      else:
        report.append(self.heading2(name))
        line = f"{self.bold('Evidence:'):s} {task.get('evidence_name')!s}"
        report.append(self.bullet(line))
        line = f"{self.bold('Status:'):s} {task.get('status')!s}"
        report.append(self.bullet(line))

        report.append(self.bullet(f"Task Id: {task.get('id')!s}"))
        report.append(
            self.bullet(f"Executed on worker {task.get('worker_name')!s}"))

        if task.get('report_data'):
          if not compact:
            report.append('')
          report.append(self.heading3('Task Reported Data'))
          report.extend(task.get('report_data').splitlines())
        if not compact:
          report.append('')

      if show_all and priority <= priority_filter:
        if not compact:
          report.append('')
        report.append(self.heading3('Saved Task Files:'))
        saved_paths = task.get('saved_paths')
        if saved_paths:
          for path in saved_paths:
            report.append(self.bullet(self.code(path)))
            if not compact:
              report.append('')
        else:
          report.append('No saved files')

      if priority <= priority_filter:
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

    sorted_tasks = sorted(
        request_data.get('tasks'), key=lambda x:
        (x['report_priority'] if x['report_priority'] else 0, x['name']))

    self.add_components([TaskMarkdownReport(task) for task in sorted_tasks])

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

  def generate_markdown(self, priority_filter=None, show_all=False) -> str:
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
      report.append(
          self.bullet(f"Evidence ID: {request_dict.get('evidence_id')}"))
      report.append('')
    except TypeError as exception:
      log.warning(f'Error formatting the Markdown report: {exception!s}')

    task_counter = defaultdict(int)
    unique_tasks = []
    for task in self.components:
      markdown = task.generate_markdown(
          priority_filter=priority_filter, show_all=show_all, compact=True)
      task_counter[markdown] += 1
      if markdown not in unique_tasks:
        unique_tasks.append(markdown)

    # Generate task list with counts
    for task in unique_tasks:
      if task_counter[task] > 1:
        report.append(f'{task} ({task_counter[task]}x)')
      else:
        report.append(task)

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

    sorted_requests = sorted(
        requests_status_list, key=lambda x: x['last_task_update_time'])
    for request_dict in sorted_requests:
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

  def generate_data_frame(self) -> pandas.DataFrame:
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
        first_column = stat_group
        self.stat_to_row(first_column, stat_dict)
        continue
      for description, inner_dict in stat_dict.items():
        first_column = f'{stat_group.split(" ")[-1]} {description}'
        self.stat_to_row(first_column, inner_dict)
    return pandas.DataFrame(self.table_dict)

  def generate_markdown(self) -> str:
    """Generates a Markdown version of task statistics.

    Returns:
      markdown(str): Markdown version of task statistics.
    """
    report = [self.heading1('Execution time statistics for Turbinia:')]
    data_frame = self.generate_data_frame()
    table = data_frame.to_markdown(index=False)
    report.append(table)
    return '\n'.join(report)

  def generate_csv(self) -> str:
    """Generates a CSV version of task statistics.

    Returns:
      csv(str): CSV version of task statistics.
    """
    return self.generate_data_frame().to_csv(index=False)


class EvidenceMarkdownReport(MarkdownReportComponent):
  """Turbinia Evidence Markdown report."""

  def __init__(self, evidence_data: dict):
    """Initializes an EvidenceMarkdownReport object."""
    super().__init__()
    self._evidence_data: dict = evidence_data

  def generate_markdown(self, level=1, show_all=False) -> str:
    """Generates a Markdown version of Evidence.

      Args:
        level (int): Indentation level.
        show_all (bool): Shows all evidence attributes if True.

      Returns:
        report (str): Markdown report.
    """
    report: list[str] = []
    evidence_dict: dict = self._evidence_data
    if not evidence_dict:
      return ''
    try:
      report.append(
          self.heading(
              f"Evidence ID: {evidence_dict.get('id', 'null')}", level))
      report.append(
          self.bullet(
              f"Evidence Name: {evidence_dict.get('_name', 'null')}", level))
      report.append(
          self.bullet(
              f"Evidence Type: {evidence_dict.get('type', 'null')}", level))
      report.append(
          self.bullet(
              f"Evidence Size: {evidence_dict.get('size', 'null')}", level))
      report.append(
          self.bullet(
              f"Request ID: {evidence_dict.get('request_id', 'null')}", level))
      report.append(self.bullet('Tasks:', level))
      report.extend(
          self.list_to_markdown(evidence_dict.get('tasks'), level + 1))
      report.append(
          self.bullet(
              f"Source Path: {evidence_dict.get('source_path', 'null')}",
              level))
      report.append(
          self.bullet(
              f"Local Path: {evidence_dict.get('local_path', 'null')}", level))
      report.append(
          self.bullet(
              f"Creation Time: {evidence_dict.get('creation_time', 'null')}",
              level))
      report.append(
          self.bullet(
              f"Last Update: {evidence_dict.get('last_update', 'null')}",
              level))

      if show_all:
        report.extend(
            self.dict_to_markdown(
                evidence_dict, level=level, excluded_keys=IMPORTANT_ATTRIBUTES))

      report.append('')

    except TypeError as exception:
      log.warning(f'Error formatting the Markdown report: {exception!s}')

    self.report = '\n'.join(report)
    return self.report


class EvidenceSummaryMarkdownReport(EvidenceMarkdownReport):
  """Turbinia Evidence Markdown report."""

  def __init__(self, summary: dict | list | int):
    """Initializes an EvidenceSummaryMarkdownReport object."""
    super().__init__({})
    self._summary = summary

  def generate_content_markdown(self, summary, level=1):
    """Generates the content Markdown summary.

      Args:
        summary (bool): Evidence summary.
        level (int): Indentation level.

      Returns:
        report (list): List with Markdown lines.
    """
    report = []
    for item in summary:
      self._evidence_data = item
      report.append(self.generate_markdown(level=(level + 1)))
    return report

  def generate_summary_markdown(self, output: str = 'keys') -> str:
    """Generates the evidence summary Markdown.

      Args:
        output (str):Type of output (keys | content | count).

      Returns:
        report (str): Markdown report.
    """
    if output == 'content':
      if isinstance(self._summary, dict):
        report = []
        for attribute, summary in self._summary.items():
          report.append(self.bullet(f'{attribute}:'))
          report.extend(self.generate_content_markdown(summary, level=2))
        return '\n'.join(report)
      return '\n'.join(self.generate_content_markdown(self._summary))
    elif isinstance(self._summary, list):
      return '\n'.join(self.list_to_markdown(self._summary, level=0))
    elif isinstance(self._summary, dict):
      return '\n'.join(
          self.dict_to_markdown(self._summary, level=0, format_keys=False))
    elif isinstance(self._summary, int):
      return self.heading1(f'{self._summary} evidences found')
