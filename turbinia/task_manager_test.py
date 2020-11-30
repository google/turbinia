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

from turbinia import config
from turbinia import TurbiniaException
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
    # pylint: disable=protected-access
    self.saved_jobs = jobs_manager.JobsManager._job_classes
    jobs_manager.JobsManager._job_classes = {}

  def tearDown(self):
    """Tears down the test class."""
    # pylint: disable=protected-access
    jobs_manager.JobsManager._job_classes = self.saved_jobs

  def testTaskManagerTasksProperty(self):
    """Basic test for task_manager Tasks property."""
    self.setResults()
    jobs_manager.JobsManager.RegisterJob(plaso.PlasoJob)
    job = jobs_manager.JobsManager.GetJobInstance('PlasoJob')
    job.tasks.extend([self.task, self.task])
    self.manager.running_jobs.extend([job, job])
    self.assertEqual(len(self.manager.tasks), 4)

  @mock.patch('turbinia.task_manager.config')
  @mock.patch('turbinia.task_manager.jobs_manager.JobsManager.GetJobs')
  @mock.patch('turbinia.task_manager.jobs_manager.JobsManager.GetJobNames')
  @mock.patch('turbinia.task_manager.BaseTaskManager._backend_setup')
  def testTaskManagerSetupDenylist(
      self, _, mock_get_job_names, mock_get_jobs, mock_config):
    """Test Task manager setup sets up correct set of jobs."""

    all_jobs = ['job1', 'job2', 'job3', 'job4', 'job5']
    jobs_denylist = ['job1']
    disabled_jobs = ['job2', 'job3']
    mock_config.DISABLED_JOBS = disabled_jobs
    mock_get_job_names.return_value = all_jobs
    mock_get_jobs.side_effect = lambda jobs: [(name, name) for name in jobs]

    # Test denylist along with disabled list in config
    self.manager.setup(jobs_denylist, [])
    self.assertListEqual(sorted(self.manager.jobs), ['job4', 'job5'])

    # Test only disabled list in config
    self.manager.setup([], [])
    self.assertListEqual(sorted(self.manager.jobs), ['job1', 'job4', 'job5'])

    # Test allowlist of item in disabled list
    self.manager.setup([], ['job2'])
    self.assertListEqual(self.manager.jobs, ['job2'])

    # Test allowlist of item not in disabled list
    self.manager.setup([], ['job4'])
    self.assertListEqual(self.manager.jobs, ['job4'])

    # Test allowlist and denylist both specified
    self.assertRaises(TurbiniaException, self.manager.setup, ['job1'], ['job2'])

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

  def testAddEvidenceDenyList(self):
    """Tests add_evidence method."""
    self.setResults()
    self.manager.add_task = mock.MagicMock()
    self.job1 = plaso.PlasoJob
    self.job2 = strings.StringsJob
    self.job1.create_tasks = mock.MagicMock(return_value=[self.task])
    self.job2.create_tasks = mock.MagicMock(return_value=[self.task])
    self.manager.jobs = [self.job1, self.job2]
    self.evidence.config['jobs_denylist'] = ['StringsJob']
    self.manager.add_evidence(self.evidence)

    # Only one Plaso job is queued after one is denylisted
    self.assertEqual(len(self.manager.running_jobs), 1)
    test_job = self.manager.running_jobs[0]
    self.assertEqual(test_job.name, 'PlasoJob')

  def testAddEvidenceAllowlist(self):
    """Tests add_evidence method."""
    self.setResults()
    self.manager.add_task = mock.MagicMock()
    self.job1 = plaso.PlasoJob
    self.job2 = strings.StringsJob
    self.job1.create_tasks = mock.MagicMock(return_value=[self.task])
    self.job2.create_tasks = mock.MagicMock(return_value=[self.task])
    self.manager.jobs = [self.job1, self.job2]
    self.evidence.config['jobs_allowlist'] = ['PlasoJob']
    self.manager.add_evidence(self.evidence)

    # Only one Plaso job is queued after one is denylisted
    self.assertEqual(len(self.manager.running_jobs), 1)
    test_job = self.manager.running_jobs[0]
    self.assertEqual(test_job.name, 'PlasoJob')

  def testCheckRequestDoneIsDone(self):
    """Basic test for check_request_done for when the request is done."""
    request_id = 'testId'
    self.job1.request_id = request_id
    self.job2.request_id = request_id
    # We want completed tasks for each Job, but no Tasks pending so that it
    # thinks they are completed.
    self.job1.completed_task_count = 1
    self.job2.completed_task_count = 1
    self.manager.running_jobs = [self.job1, self.job2]
    self.assertTrue(self.manager.check_request_done(request_id))

  def testCheckRequestDoneNoCompletedTasks(self):
    """Test for check_request_done no tasks have been completed."""
    request_id = 'testId'
    self.job1.request_id = request_id
    self.job2.request_id = request_id
    self.manager.running_jobs = [self.job1, self.job2]
    # With no completed tasks the Jobs will show as not yet done.
    self.assertFalse(self.manager.check_request_done(request_id))

  def testCheckRequestDonePendingTasks(self):
    """Test for check_request_done when Tasks are pending."""
    request_id = 'testId'
    self.job1.request_id = request_id
    self.job2.request_id = request_id
    self.job1.completed_task_count = 1
    self.job2.completed_task_count = 1
    self.job1.tasks = [self.task]
    self.manager.running_jobs = [self.job1, self.job2]
    # With no completed tasks the Jobs will show as not yet done.
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

  @mock.patch('turbinia.state_manager.get_state_manager')
  def testFinalizeResult(self, _):
    """Tests process_result method."""
    self.result.setup(self.task)
    job_id = 'testJobID'
    self.job1.id = job_id
    self.result.job_id = job_id
    self.result.evidence.append(self.evidence)
    self.manager.add_evidence = mock.MagicMock()
    self.manager.running_jobs.append(self.job1)
    test_job = self.manager.process_result(self.result)
    self.assertEqual(test_job.id, job_id)
    self.assertEqual(test_job, self.manager.running_jobs[0])
    self.assertEqual(test_job.evidence.collection[0], self.evidence)
    self.manager.add_evidence.assert_called_with(self.evidence)

  @mock.patch('turbinia.state_manager.get_state_manager')
  def testFinalizeResultBadEvidence(self, _):
    """Tests process_result method with bad input evidence."""
    self.result.setup(self.task)
    job_id = 'testJobID'
    self.job1.id = job_id
    self.result.job_id = job_id
    self.result.evidence = None
    self.assertIsNone(self.manager.process_result(self.result))
    self.assertIsInstance(self.result.evidence, list)

  @mock.patch('turbinia.task_manager.state_manager.get_state_manager')
  def testFinalizeJobGenerateJobFinalizeTasks(self, _):
    """Tests process_job method generates Job finalize Task."""
    request_id = 'testRequestID'
    self.task.id = 'createdFinalizeTask'
    self.plaso_task.id = 'originalTask'
    self.job1.request_id = request_id
    # We'll use self.task as the finalize task that gets created.
    self.job1.create_final_task = mock.MagicMock(return_value=self.task)
    self.job1.evidence.add_evidence(self.evidence)
    self.manager.enqueue_task = mock.MagicMock()
    self.job1.tasks.append(self.plaso_task)
    self.manager.running_jobs.append(self.job1)
    # Job has one task that is not a finalize task, so it will generate job
    # finalize tasks.
    self.manager.process_job(self.job1, self.plaso_task)

    self.job1.create_final_task.assert_called()
    self.manager.enqueue_task.assert_called()
    test_task, test_evidence = self.manager.enqueue_task.call_args[0]
    # Make sure the evidence originally associated with the job is the same as
    # the new evidence collection.
    self.assertListEqual(test_evidence.collection, [self.evidence])
    self.assertEqual(test_task.id, 'createdFinalizeTask')
    self.assertFalse(self.job1.is_finalized)
    # We should only have our new finalize task running, and the old task should
    # be gone.
    self.assertListEqual(self.manager.running_jobs[0].tasks, [self.task])

  def testFinalizeJobGenerateRequestFinalizeTasks(self):
    """Tests process_job method generates Request finalize Task."""
    request_id = 'testRequestID'
    self.task.is_finalize_task = True
    self.job1.request_id = request_id
    self.job1.evidence.add_evidence(self.evidence)
    self.job1.create_final_task = mock.MagicMock()
    self.job1.tasks.append(self.task)
    self.manager.generate_request_finalize_tasks = mock.MagicMock()
    self.manager.remove_jobs = mock.MagicMock()
    self.manager.running_jobs.append(self.job1)
    # Job has one task, and it is a finalze_task.
    self.manager.process_job(self.job1, self.task)

    # Job won't be finalized because the finalize job task has not completed.
    self.assertFalse(self.job1.is_finalized)
    # Because the task is a finalize task it shouldn't generate job finalize.
    self.job1.create_final_task.assert_not_called()
    self.manager.generate_request_finalize_tasks.assert_called_with(self.job1)
    self.manager.remove_jobs.assert_not_called()

  def testFinalizeJobClosingRequest(self):
    """Tests that process_job method removes jobs when request is finalized."""
    request_id = 'testRequestID'
    self.plaso_task.request_id = request_id
    self.job1.request_id = request_id
    self.job2.request_id = 'ThisIsADifferentRequest'
    self.job1.evidence.add_evidence(self.evidence)
    self.job1.tasks.append(self.plaso_task)
    self.job1.completed_task_count = 1
    self.job1.is_finalize_job = True
    self.manager.generate_request_finalize_tasks = mock.MagicMock()
    self.manager.running_jobs.extend([self.job1, self.job2])
    self.manager.process_job(self.job1, self.plaso_task)

    self.manager.generate_request_finalize_tasks.assert_not_called()
    # The Job for our request was removed, but the second job still remains
    self.assertListEqual(self.manager.running_jobs, [self.job2])
    self.assertListEqual(self.job1.tasks, [])
    self.assertTrue(self.job1.is_finalized)

  def testRun(self):
    """Test the run() method."""
    self.manager.get_evidence = mock.MagicMock(return_value=[self.evidence])
    self.manager.add_evidence = mock.MagicMock()
    self.task.result = self.result
    self.manager.process_tasks = mock.MagicMock(return_value=[self.task])
    self.manager.process_result = mock.MagicMock(return_value=self.job1)
    self.manager.process_job = mock.MagicMock()
    self.manager.run(under_test=True)

    self.manager.add_evidence.assert_called_with(self.evidence)
    self.manager.process_result.assert_called_with(self.result)
    self.manager.process_job.assert_called_with(self.job1, self.task)
