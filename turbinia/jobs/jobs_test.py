# -*- coding: utf-8 -*-
# Copyright 2016 Google Inc.
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
"""Tests for jobs __init__."""

from __future__ import unicode_literals

import json
import os
import tempfile
import unittest
import mock

from turbinia import jobs
from turbinia.jobs.worker_stat import StatJob
from turbinia.jobs.plaso import PlasoJob
from turbinia import TurbiniaException


class TestTurbiniaJob(unittest.TestCase):
  """Test jobs module."""
  def setUp(self):
    self.test_jobs = [StatJob(), PlasoJob()]
    self.test_jobs_names = [job.name for job in self.test_jobs]

  def testTurbiniaJobGetJobs(self):
    """Test that we get the right list of Job objects back."""
    jobs_list = jobs.get_jobs(jobs_list=self.test_jobs)
    self.assertEqual(len(jobs_list), len(self.test_jobs))
    self.assertTrue(min([isinstance(j, jobs.TurbiniaJob) for j in jobs_list]))
    self.assertListEqual([job.name for job in jobs_list], self.test_jobs_names)

  def testTurbiniaJobGetJobsBlacklist(self):
    """Test that jobs_blacklist blacklists."""
    jobs_blacklist = [self.test_jobs_names[0]]
    jobs_not_blacklisted = self.test_jobs_names[1:]
    jobs_list = jobs.get_jobs(
        jobs_blacklist=jobs_blacklist, jobs_list=self.test_jobs)
    jobs_list_names = [job.name for job in jobs_list]

    self.assertEqual(len(jobs_list), len(self.test_jobs) - len(jobs_blacklist))
    self.assertTrue(min([isinstance(j, jobs.TurbiniaJob) for j in jobs_list]))
    self.assertNotEqual(jobs_list_names, self.test_jobs_names)
    self.assertNotIn(jobs_blacklist[0], jobs_list_names)
    self.assertIn(jobs_list_names[0], jobs_not_blacklisted)

  def testTurbiniaJobGetJobsWhitelist(self):
    """Test that job_whitelist whitelists."""
    jobs_whitelist = [self.test_jobs_names[0]]
    jobs_not_whitelisted = self.test_jobs_names[1:]
    jobs_list = jobs.get_jobs(
        jobs_whitelist=jobs_whitelist, jobs_list=self.test_jobs)
    jobs_list_names = [job.name for job in jobs_list]

    self.assertEqual(len(jobs_list), len(jobs_whitelist))
    self.assertNotEqual(jobs_list_names, self.test_jobs_names)
    self.assertIn(jobs_whitelist[0], jobs_list_names)
    self.assertNotIn(jobs_list_names[0], jobs_not_whitelisted)

  def testTurbiniaJobGetJobsWhiteAndBlacklist(self):
    """Test that we get all Jobs back when specifying both white/black lists."""
    jobs_list = jobs.get_jobs(
        jobs_blacklist=['nojob'], jobs_whitelist=['nojob'], jobs_list=self.test_jobs)
    self.assertEqual(len(jobs_list), len(self.test_jobs))
    self.assertTrue(min([isinstance(j, jobs.TurbiniaJob) for j in jobs_list]))
    self.assertListEqual([job.name for job in jobs_list], self.test_jobs_names)
