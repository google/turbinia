#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for the job manager."""

from __future__ import unicode_literals

import unittest

from turbinia.jobs import interface
from turbinia.jobs import manager


class TestJob1(interface.TurbiniaJob):
  """Test job."""

  NAME = 'testjob1'

  # pylint: disable=unused-argument
  def create_tasks(self, evidence):
    """Returns None, for testing."""
    return None

class TestJob2(interface.TurbiniaJob):
  """Test job."""

  NAME = 'testjob2'

  # pylint: disable=unused-argument
  def create_tasks(self, evidence):
    """Returns None, for testing."""
    return None

class JobsManagerTest(unittest.TestCase):
  """Tests for the jobs manager."""

  # pylint: disable=protected-access

  def tearDown(self):
    """Cleans up after running an individual test."""
    # Deregister the test jobs if the test failed.
    try:
      manager.JobsManager.DeregisterJob(TestJob1)
    except KeyError:
      pass
    try:
      manager.JobsManager.DeregisterJob(TestJob2)
    except KeyError:
      pass

  def testJobRegistration(self):
    """Tests the registration and deregistration of jobs."""
    number_of_jobs = len(manager.JobsManager._job_classes)
    manager.JobsManager.RegisterJob(TestJob1)
    self.assertEqual(
        number_of_jobs + 1, len(
            manager.JobsManager._job_classes))

    with self.assertRaises(KeyError):
      manager.JobsManager.RegisterJob(TestJob1)

    manager.JobsManager.DeregisterJob(TestJob1)

    self.assertEqual(
        number_of_jobs, len(manager.JobsManager._job_classes))

    number_of_jobs = len(manager.JobsManager._job_classes)
    manager.JobsManager.RegisterJobs([TestJob1, TestJob2])
    self.assertEqual(
        number_of_jobs + 2, len(
            manager.JobsManager._job_classes))

    with self.assertRaises(KeyError):
      manager.JobsManager.RegisterJob(TestJob1)

    manager.JobsManager.DeregisterJob(TestJob1)
    manager.JobsManager.DeregisterJob(TestJob2)

    self.assertEqual(
        number_of_jobs, len(manager.JobsManager._job_classes))


  def testGetJobInstance(self):
    """Tests the GetJobInstance function."""
    manager.JobsManager.RegisterJob(TestJob1)
    job = manager.JobsManager.GetJobInstance('testjob1')
    self.assertIsNotNone(job)
    self.assertEqual(job.NAME, 'testjob1')

    with self.assertRaises(KeyError):
      manager.JobsManager.GetJobInstance('bogus')
    manager.JobsManager.DeregisterJob(TestJob1)

  def testGetJobInstances(self):
    """Tests getting job objects by name."""
    manager.JobsManager.RegisterJob(TestJob1)
    job_names = manager.JobsManager.GetJobNames()
    jobs = manager.JobsManager.GetJobInstances(job_names)
    self.assertEqual(len(job_names), len(jobs))
    for job in jobs:
      self.assertIsInstance(job, interface.TurbiniaJob)


if __name__ == '__main__':
  unittest.main()
