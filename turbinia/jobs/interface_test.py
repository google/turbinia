# -*- coding: utf-8 -*-
# Copyright 2019 Google Inc.
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
"""Tests for Turbinia Jobs interface."""

from __future__ import unicode_literals

from turbinia import evidence
from turbinia.jobs import interface
from turbinia.workers.workers_test import TestTurbiniaTaskBase


class TestJobsInterface(TestTurbiniaTaskBase):
  """Tests Jobs interface."""

  def setUp(self):
    super(TestJobsInterface, self).setUp()
    self.job = interface.TurbiniaJob()

  def testCheckDone(self):
    """Tests check_done() method."""
    self.job.completed_task_count = 1
    self.assertTrue(self.job.check_done())

  def testCheckDoneNoCompletedCount(self):
    """Tests check_done() method."""
    self.assertFalse(self.job.check_done())

  def testCheckDoneWithTasks(self):
    """Tests check_done() method."""
    self.job.completed_task_count = 1
    self.job.tasks.append(self.task)
    self.assertFalse(self.job.check_done())

  def testRemoveTask(self):
    """Tests remove_task."""
    task_id = self.task.id
    self.job.tasks.append(self.task)
    self.assertTrue(self.job.remove_task(task_id))
    self.assertListEqual(self.job.tasks, [])

  def testRemoveTaskUnknownTask(self):
    """Tests remove_task."""
    task_id = 'noSuchTask'
    self.job.tasks.append(self.task)
    self.assertFalse(self.job.remove_task(task_id))
    self.assertListEqual(self.job.tasks, [self.task])
