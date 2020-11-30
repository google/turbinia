#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Tests for the job manager."""

from __future__ import unicode_literals

import unittest

from turbinia import TurbiniaException
from turbinia.jobs import interface
from turbinia.jobs import manager


class TestJob1(interface.TurbiniaJob):
  """Test job."""

  NAME = 'testjob1'

  # pylint: disable=unused-argument
  def create_tasks(self, evidence):
    """Returns None, for testing."""
    return None


class TestJob2(TestJob1):
  """Test job."""

  NAME = 'testjob2'


class TestJob3(TestJob1):
  """Test job."""

  NAME = 'testjob3'


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
    self.assertEqual(number_of_jobs + 1, len(manager.JobsManager._job_classes))

    with self.assertRaises(KeyError):
      manager.JobsManager.RegisterJob(TestJob1)

    manager.JobsManager.DeregisterJob(TestJob1)

    self.assertEqual(number_of_jobs, len(manager.JobsManager._job_classes))

    number_of_jobs = len(manager.JobsManager._job_classes)
    manager.JobsManager.RegisterJobs([TestJob1, TestJob2])
    self.assertEqual(number_of_jobs + 2, len(manager.JobsManager._job_classes))

    with self.assertRaises(KeyError):
      manager.JobsManager.RegisterJob(TestJob1)

    manager.JobsManager.DeregisterJob(TestJob1)
    manager.JobsManager.DeregisterJob(TestJob2)

    self.assertEqual(number_of_jobs, len(manager.JobsManager._job_classes))

  def testJobDeregistrationWithUnknownAllowlist(self):
    """Test that deregistration throws error when allowlisting unknown Job."""
    self.assertRaises(
        TurbiniaException, manager.JobsManager.DeregisterJobs, [], ['NoJob'])

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

  def testFilterJobNamesEmptyLists(self):
    """Test FilterJobNames() with no filters."""
    job_names = ['testjob1', 'testjob2']
    return_job_names = manager.JobsManager.FilterJobNames(
        job_names, jobs_denylist=[], jobs_allowlist=[])
    self.assertListEqual(job_names, return_job_names)

  def testFilterJobNamesDenyList(self):
    """Test FilterJobNames() with jobs_denylist."""
    job_names = ['testjob1', 'testjob2']
    return_job_names = manager.JobsManager.FilterJobNames(
        job_names, jobs_denylist=[job_names[0]], jobs_allowlist=[])
    self.assertListEqual(job_names[1:], return_job_names)

  def testFilterJobObjectsDenyList(self):
    """Test FilterJobObjects() with jobs_denylist and objects."""
    jobs = [TestJob1(), TestJob2()]
    return_jobs = manager.JobsManager.FilterJobObjects(
        jobs, jobs_denylist=[jobs[0].name], jobs_allowlist=[])
    self.assertListEqual(jobs[1:], return_jobs)

  def testFilterJobNamesAllowList(self):
    """Test FilterJobNames() with jobs_allowlist."""
    job_names = ['testjob1', 'testjob2']
    return_job_names = manager.JobsManager.FilterJobNames(
        job_names, jobs_denylist=[], jobs_allowlist=[job_names[0]])
    self.assertListEqual(job_names[:1], return_job_names)

  def testFilterJobObjectsAllowList(self):
    """Test FilterJobObjects() with jobs_allowlist."""
    jobs = [TestJob1(), TestJob2()]
    return_jobs = manager.JobsManager.FilterJobObjects(
        jobs, jobs_denylist=[], jobs_allowlist=[jobs[1].name])
    self.assertListEqual(jobs[1:], return_jobs)

  def testFilterJobNamesException(self):
    """Test FilterJobNames() with both jobs_denylist and jobs_allowlist."""
    job_names = ['testjob1', 'testjob2']
    self.assertRaises(
        TurbiniaException, manager.JobsManager.FilterJobNames, job_names,
        jobs_denylist=['a'], jobs_allowlist=['b'])

  def testFilterJobNamesMixedCase(self):
    """Test FilterJobNames() with mixed case inputs."""
    job_names = ['testjob1', 'testjob2']
    return_job_names = manager.JobsManager.FilterJobNames(
        job_names, jobs_denylist=[], jobs_allowlist=['TESTJOB1'])
    self.assertListEqual(job_names[:1], return_job_names)


if __name__ == '__main__':
  unittest.main()
