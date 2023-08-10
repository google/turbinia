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

log = logging.getLogger('turbinia')

IMPORTANT_ATTRIBUTES = {
    'id', '_name', 'type', 'size', 'request_id', 'tasks', 'source_path',
    'local_path', 'creation_time', 'last_updated'
}


def echo_json(json_data: dict) -> None:
  """Pretty print JSON data."""
  if isinstance(json_data, (dict, list, int)):
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

  def heading(self, text, number):
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

  def list_to_markdown(self, original_list, level=1):
    if not original_list:
      return [self.bullet('[EMPTY LIST]', level)]
    report = []
    for item in original_list:
      if isinstance(item, dict):
        report.extend(self.dict_to_markdown(item, level + 1))
      elif isinstance(item, list):
        report.extend(self.list_to_markdown(item, level + 1))
      else:
        report.append(self.bullet(item, level))
    return report

  def dict_to_markdown(
      self, original_dict, level=1, ignore=None, show_null=False,
      format_name=True):
    if not original_dict:
      return [self.bullet('[EMPTY DICTIONARY]', level)]
    report: list[str] = []
    for key, value in original_dict.items():
      if (ignore and
          key in ignore) or not (show_null or value or value is False):
        continue
      name = key.replace('_', ' ').title() if format_name else key
      if isinstance(value, dict):
        report.append(self.bullet(f'{name}:', level))
        report.extend(self.dict_to_markdown(value, level + 1))
      elif isinstance(value, list):
        report.append(self.bullet(f'{name}:', level))
        report.extend(self.list_to_markdown(value, level + 1))
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

  def __init__(self, request_data: dict):
    super().__init__()
    self._request_data: dict = request_data

  def generate_markdown(self) -> str:
    """Generates a Markdown version of tasks per worker."""
    raise NotImplementedError


class EvidenceMarkdownReport(MarkdownReportComponent):
  """Turbinia Evidence Markdown report."""

  def __init__(self, evidence_data: dict):
    """Initializes a EvidenceMarkdownReport object."""
    super().__init__()
    self._evidence_data: dict = evidence_data

  def generate_markdown(
      self, level=1, show_ignored=False, show_null=False) -> str:
    """Generates a Markdown version of Requests results."""
    report: list[str] = []
    evidence_dict: dict = self._evidence_data
    if not evidence_dict:
      return ''
    try:
      report.append(
          self.heading(
              f"Evidence ID: {evidence_dict.get('id', 'null')}", level + 1))
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
              f"Creation Time: {evidence_dict.get('creation_time', 'null'),}",
              level))
      report.append(
          self.bullet(
              f"Last Update: {evidence_dict.get('last_updated', 'null')}",
              level))

      if show_ignored:
        report.extend(
            self.dict_to_markdown(
                evidence_dict, level, IMPORTANT_ATTRIBUTES, show_null))

      report.append('')

    except TypeError as exception:
      log.warning(f'Error formatting the Markdown report: {exception!s}')

    self.report = '\n'.join(report)
    return self.report


class EvidenceSummaryMarkdownReport(EvidenceMarkdownReport):
  """Turbinia Evidence Markdown report."""

  def __init__(self, summary: dict | list | int):
    """Initializes a EvidenceMarkdownReport object."""
    super().__init__({})
    self._summary = summary

  def generate_value_markdown(self, summary, level=1):
    report = []
    for item in summary:
      self._evidence_data = item
      report.append(self.generate_markdown(level + 1))
    return report

  def generate_summary_markdown(self, output='keys'):
    if output == 'values':
      if isinstance(self._summary, dict):
        report = []
        for attribute_value, value in self._summary.items():
          report.append(self.bullet(f'{attribute_value}:'))
          report.extend(self.generate_value_markdown(value, 2))
        return '\n'.join(report)
      return '\n'.join(self.generate_value_markdown(self._summary))
    elif isinstance(self._summary, list):
      return '\n'.join(self.list_to_markdown(self._summary))
    elif isinstance(self._summary, dict):
      return '\n'.join(self.dict_to_markdown(self._summary, format_name=False))
    elif isinstance(self._summary, int):
      return self.heading2(f'{self._summary} evidences found')
