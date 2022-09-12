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


class MarkdownReportComponent(ABC):
  """Components for generating Turbinia request/task
      markdown reports.
  """

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
    return '**{0:s}**'.format(text.strip())

  def heading1(self, text):
    """Formats text as heading 1 in Markdown format.

    Args:
        text(string): Text to format

    Return:
        string: Formatted text.
    """
    return '# {0:s}'.format(text.strip())

  def heading2(self, text):
    """Formats text as heading 2 in Markdown format.

    Args:
        text(string): Text to format

    Return:
        string: Formatted text.
    """
    return '## {0:s}'.format(text.strip())

  def heading3(self, text):
    """Formats text as heading 3 in Markdown format.

    Args:
        text(string): Text to format

    Return:
        string: Formatted text.
    """
    return '### {0:s}'.format(text.strip())

  def heading4(self, text):
    """Formats text as heading 4 in Markdown format.

    Args:
        text(string): Text to format

    Return:
        string: Formatted text.
    """
    return '#### {0:s}'.format(text.strip())

  def heading5(self, text):
    """Formats text as heading 5 in Markdown format.
     Args:
        text(string): Text to format
     Return:
        string: Formatted text.
    """
    return '##### {0:s}'.format(text.strip())

  def bullet(self, text, level=1):
    """Formats text as a bullet in Markdown format.

      Args:
        text(string): Text to format
      Return:
        string: Formatted text.
    """
    return '{0:s}* {1:s}'.format('    ' * (level - 1), text.strip())

  def code(self, text):
    """Formats text as code in Markdown format.

      Args:
          text(string): Text to format

     Return:
          string: Formatted text.
    """
    return '`{0:s}`'.format(text.strip())

  def add(self, component: MarkdownReportComponent) -> None:
    pass

  def add_components(self, components: list[MarkdownReportComponent]) -> None:
    pass

  def remove(self, component: MarkdownReportComponent) -> None:
    pass

  @abstractmethod
  def generate_markdown(self) -> str:
    pass


class TaskMarkdownReport(MarkdownReportComponent):
  """Turbinia Task markdown report."""

  def __init__(self, request_data: dict = None):
    """Initialize TaskMarkdownReport"""
    self._report: str = None
    self._request_data: dict = request_data

  @property
  def report(self):
    """Returns the markdown report text."""
    return self._report

  @report.setter
  def report(self, report):
    self._report = report

  def generate_markdown(self) -> str:
    """Generate a markdown report."""
    report: list[str] = []
    task: dict = self._request_data
    if not task:
      return {}

    report.append(self.heading2(task.get('name')))
    line = '{0:s} {1!s}'.format(
        self.bold('Evidence:'), task.get('evidence_name'))
    report.append(self.bullet(line))
    line = '{0:s} {1:s}'.format(self.bold('Status:'), task.get('status'))
    report.append(self.bullet(line))
    report.append(self.bullet('Task Id: {0!s}'.format(task.get('id'))))
    report.append(
        self.bullet('Executed on worker {0!s}'.format(task.get('worker_name'))))
    if task.get('report_data'):
      report.append('')
      report.append(self.heading3('Task Reported Data'))
      report.extend(task.get('report_data').splitlines())
    report.append('')
    report.append(self.heading3('Saved Task Files:'))
    for path in task.get('saved_paths'):
      report.append(self.bullet(self.code(path)))
      report.append('')

    self.report = '\n'.join(report)
    return self.report


class RequestMarkdownReport(MarkdownReportComponent):
  """Turbinia Request Markdown report."""

  def __init__(self, request_data: dict):
    """seadsasd"""
    self._tasks: list[TaskMarkdownReport] = []
    self._report: str = None
    self._request_data: dict = request_data

    if request_data:
      tasks = [TaskMarkdownReport(task) for task in request_data.get('tasks')]
      self.add_components(tasks)

  def add(self, component: MarkdownReportComponent) -> None:
    if component:
      self._tasks.append(component)
      component.parent = self

  def remove(self, component: MarkdownReportComponent) -> None:
    self._tasks.remove(component)
    component.parent = None

  def add_components(self, components: list[MarkdownReportComponent]) -> None:
    if components:
      for component in components:
        self._tasks.append(component)
        component.parent = self

  @property
  def report(self):
    """Returns the markdown report text."""
    return self._report

  @report.setter
  def report(self, report):
    self._report = report

  def generate_markdown(self) -> str:
    """Generates a Markdown version of Requests results."""
    report: list[str] = []
    request_dict: dict = self._request_data
    if not request_dict:
      return ''

    report.append(
        self.heading2(
            'Request ID: {0!s}'.format(request_dict.get('request_id'))))
    report.append(
        self.bullet(
            'Last Update: {0!s}'.format(
                request_dict.get('last_task_update_time'))))
    report.append(
        self.bullet('Requester: {0!s}'.format(request_dict.get('requester'))))
    report.append(
        self.bullet('Reason: {0!s}'.format(request_dict.get('reason'))))
    report.append(
        self.bullet('Status: {0!s}'.format(request_dict.get('status'))))
    report.append(
        self.bullet(
            'Failed tasks: {0:d}'.format(request_dict.get('failed_tasks'))))
    report.append(
        self.bullet(
            'Running tasks: {0:d}'.format(request_dict.get('running_tasks'))))
    report.append(
        self.bullet(
            'Successful tasks: {0:d}'.format(
                request_dict.get('successful_tasks'))))
    report.append(
        self.bullet('Task Count: {0:d}'.format(request_dict.get('task_count'))))
    report.append(
        self.bullet(
            'Queued tasks: {0:d}'.format(request_dict.get('queued_tasks'))))
    report.append('')

    for task in self._tasks:
      report.append(task.generate_markdown())

    self.report = '\n'.join(report)
    return self.report


class SummaryMarkdownReport(MarkdownReportComponent):
  """A markdown report summary of all Turbinia Requests."""

  def __init__(self, requests_summary: list[dict]):
    """Initialize SummaryMarkdownReport."""
    self._requests_summary = requests_summary
    self._report = None

  @property
  def report(self):
    """Returns the markdown report text."""
    return self._report

  @report.setter
  def report(self, report):
    self._report = report

  def generate_markdown(self) -> str:
    """Generate a Markdown version of Requests summary results."""
    if not self._requests_summary:
      return ''
    report: list[str] = []
    requests_status_list = self._requests_summary.get('requests_status')
    for request_dict in requests_status_list:
      request_report = RequestMarkdownReport(request_dict).generate_markdown()
      report.append(request_report)

    self.report = '\n'.join(report)
    return self.report
