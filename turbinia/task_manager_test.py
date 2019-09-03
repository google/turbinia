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
"""Tests for Turbinia task_manager module."""

from __future__ import unicode_literals

import mock

from turbinia import task_manager
from turbinia.jobs import manager as jobs_manager
from turbinia.jobs import plaso
from turbinia.jobs import strings
from turbinia.workers.workers_test import TestTurbiniaTaskBase


class TestTaskManager(TestTurbiniaTaskBase):
  """Tests the task_manager module."""

  @mock.patch('turbinia.task_manager.state_manager.get_state_manager')
  def setUp(self, _):
    """Sets up the test class."""
    super(TestTaskManager, self).setUp()
    self.manager = task_manager.BaseTaskManager()
    self.job1 = plaso.PlasoJob()
    self.job2 = strings.StringsJob()

  def testTaskManagerTasksProperty(self):
    """Basic test for task_manager Tasks property."""
    self.setResults()
    job = jobs_manager.JobsManager.GetJobInstance('PlasoJob')
    job.tasks.extend([self.task, self.task])
    self.manager.running_jobs.extend([job, job])
    self.assertEqual(len(self.manager.tasks), 4)

  def testAddEvidence(self):
    """Tests add_evidence method."""
    self.setResults()
    request_id = 'testRequestID'
    self.evidence.request_id = request_id
    self.manager.add_task = mock.MagicMock()
    job = plaso.PlasoJob
    job.create_tasks = mock.MagicMock(return_value=[self.task])
    self.manager.jobs = [job]
    self.manager.add_evidence(self.evidence)

    self.manager.add_task.assert_called()
    test_job = self.manager.running_jobs[0]
    test_job.create_tasks.assert_called()
    self.assertEqual(test_job.request_id, request_id)
    self.assertEqual(test_job.evidence.request_id, request_id)
    self.assertIn(test_job, self.manager.running_jobs)

  def testAddEvidenceBlackList(self):
    """Tests add_evidence method."""
    self.setResults()
    self.manager.add_task = mock.MagicMock()
    self.job1 = plaso.PlasoJob
    self.job2 = strings.StringsJob
    self.job1.create_tasks = mock.MagicMock(return_value=[self.task])
    self.job2.create_tasks = mock.MagicMock(return_value=[self.task])
    self.manager.jobs = [self.job1, self.job2]
    self.evidence.config['jobs_blacklist'] = ['StringsJob']
    self.manager.add_evidence(self.evidence)

    # Only one Plaso job is queued after one is blacklisted
    self.assertEqual(len(self.manager.running_jobs), 1)
    test_job = self.manager.running_jobs[0]
    self.assertEqual(test_job.name, 'PlasoJob')

  def testAddEvidenceWhitelist(self):
    """Tests add_evidence method."""
    self.setResults()
    self.manager.add_task = mock.MagicMock()
    self.job1 = plaso.PlasoJob
    self.job2 = strings.StringsJob
    self.job1.create_tasks = mock.MagicMock(return_value=[self.task])
    self.job2.create_tasks = mock.MagicMock(return_value=[self.task])
    self.manager.jobs = [self.job1, self.job2]
    self.evidence.config['jobs_whitelist'] = ['PlasoJob']
    self.manager.add_evidence(self.evidence)

    # Only one Plaso job is queued after one is blacklisted
    self.assertEqual(len(self.manager.running_jobs), 1)
    test_job = self.manager.running_jobs[0]
    self.assertEqual(test_job.name, 'PlasoJob')

  def testCheckRequestDoneIsDone(self):
    """Basic test for check_request_done for when the request is done."""
    request_id = 'testId'
    self.job1.request_id = request_id
    self.job2.request_id = request_id
    # We want evidence associated with each Job, but no Tasks so that it thinks
    # they are completed.
    self.job1.evidence.collection.append(self.evidence)
    self.job2.evidence.collection.append(self.evidence)
    self.manager.running_jobs = [self.job1, self.job2]
    self.assertTrue(self.manager.check_request_done(request_id))

  def testCheckRequestDoneIsNotDone(self):
    """Basic test for check_request_done for when the request is done."""
    request_id = 'testId'
    self.job1.request_id = request_id
    self.job2.request_id = request_id
    self.manager.running_jobs = [self.job1, self.job2]
    # With no associated evidence the Jobs will show as not yet done.
    self.assertFalse(self.manager.check_request_done(request_id))

  def testGetJob(self):
    """Tests get_job method."""
    self.setResults()
    job_id = 'testID'
    self.job1.id = job_id
    self.job2.id = 'NotMyJob'
    self.manager.running_jobs = [self.job1, self.job2]
    test_job = self.manager.get_job(job_id)
    self.assertEqual(test_job.name, 'PlasoJob')
    self.assertEqual(test_job.id, job_id)

  def testAddTask(self):
    """Tests add_task method."""
    request_id = 'testID'
    self.evidence.request_id = request_id
    self.manager.enqueue_task = mock.MagicMock()
    self.manager.add_task(self.task, self.job1, self.evidence)
    self.assertEqual(self.task.request_id, request_id)
    self.assertListEqual(self.job1.tasks, [self.task])
    self.manager.enqueue_task.assert_called()

  def testRemoveJob(self):
    """Tests remove_job method."""
    job_id = 'testID'
    self.job1.id = job_id
    self.manager.running_jobs.extend([self.job1, self.job2])
    self.assertTrue(self.manager.remove_job(job_id))
    self.assertListEqual(self.manager.running_jobs, [self.job2])

  def testFinalizeResult(self):
    """Tests finalize_result method."""
    job_id = 'testJobID'
    self.job1.id = job_id
    self.result.job_id = job_id
    self.result.evidence.append(self.evidence)
    self.manager.add_evidence = mock.MagicMock()
    self.manager.running_jobs.append(self.job1)
    test_job = self.manager.finalize_result(self.result)
    self.assertEqual(test_job.id, job_id)
    self.assertEqual(test_job, self.manager.running_jobs[0])
    self.assertEqual(test_job.evidence.collection[0], self.evidence)
    self.manager.add_evidence.assert_called_with(self.evidence)

  def testFinalizeResultBadEvidence(self):
    """Tests finalize_result method with bad input evidence."""
    job_id = 'testJobID'
    self.job1.id = job_id
    self.result.job_id = job_id
    self.result.evidence = None
    self.assertIsNone(self.manager.finalize_result(self.result))
    self.assertIsInstance(self.result.evidence, list)

  def testFinalizeJob(self):
    """Tests finalize_job method."""
    task_id = 'testTaskID'
    self.task.id = task_id
    self.job1.request_id = 'testRequestID'
    self.job1.create_final_task = mock.MagicMock()
    self.job1.evidence.add_evidence(self.evidence)
    self.manager.add_task = mock.MagicMock()
    self.job1.tasks.append(self.task)
    self.manager.running_jobs.append(self.job1)
    self.manager.finalize_job(self.job1, task_id)

    self.job1.create_final_task.assert_called()
    self.manager.add_task.assert_called()
    _, __, test_evidence = self.manager.add_task.call_args[0]
    self.assertListEqual(test_evidence.collection, [self.evidence])
    self.assertListEqual(self.manager.running_jobs[0].tasks, [])

  def testRun(self):
    """Test the run() method."""
    result_id = 'testResultID'
    self.manager.get_evidence = mock.MagicMock(return_value=[self.evidence])
    self.manager.add_evidence = mock.MagicMock()
    self.result.id = result_id
    self.task.result = self.result
    self.manager.process_tasks = mock.MagicMock(return_value=[self.task])
    self.manager.finalize_result = mock.MagicMock(return_value=self.job1)
    self.manager.finalize_job = mock.MagicMock()
    self.manager.run(under_test=True)

    self.manager.add_evidence.assert_called_with(self.evidence)
    self.manager.finalize_result.assert_called_with(self.result)
    self.manager.finalize_job.assert_called_with(self.job1, result_id)
