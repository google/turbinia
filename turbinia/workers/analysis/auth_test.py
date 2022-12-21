# -*- coding: utf-8 -*-
# Copyright 2021 Google Inc.
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
"""AuthAnalyzer test class"""

import json
import logging
import pandas as pd
import unittest

from turbinia.workers.analysis.auth import AuthAnalyzer

log = logging.getLogger('turbinia')
log.setLevel(logging.DEBUG)


class TestAuthAnalyzer(unittest.TestCase):
  """Test class for AuthAnalyzer"""

  EXPECTED_IP_SUMMARY = {
      'summary_type': 'source_ip',
      'source_ip': '146.246.166.225',
      'domain': '',
      'username': '',
      'first_seen': 1657114421,
      'last_seen': 1665969305,
      'first_auth_timestamp': 0,
      'first_auth_ip': '',
      'first_auth_username': '',
      'success_source_ip_list': [],
      'success_username_list': [],
      'total_success_events': 0,
      'total_failed_events': 39,
      'distinct_source_ip_count': 1,
      'distinct_username_count': 39,
      'top_source_ips': {
          '146.246.166.225': 39
      },
      'top_usernames': {
          'abbotsen': 1,
          'antigen': 1,
          'bax': 1,
          'celebrated': 1,
          'coreencorel': 1,
          'delft': 1,
          'dissent': 1,
          'dissimilation': 1,
          'enchanting': 1,
          'essam': 1
      }
  }

  EXPECTED_USER_SUMMARY = {
      'summary_type': 'username',
      'source_ip': '',
      'domain': '',
      'username': 'gametogenesis',
      'first_seen': 1665969305,
      'last_seen': 1665969305,
      'first_auth_timestamp': 0,
      'first_auth_ip': '',
      'first_auth_username': '',
      'success_source_ip_list': [],
      'success_username_list': [],
      'total_success_events': 0,
      'total_failed_events': 1,
      'distinct_source_ip_count': 1,
      'distinct_username_count': 1,
      'top_source_ips': {
          '146.246.166.225': 1
      },
      'top_usernames': {
          'gametogenesis': 1
      }
  }

  def test_get_ip_summary(self):
    """Test get_ip_summary method."""
    aa = AuthAnalyzer(
        name='analyzer.auth', display_name='Auth Analyzer',
        description='Authentication analyzer')

    df = pd.read_csv('test_data/ssh_auth_data.csv')
    aa.set_dataframe(df)

    summary = aa.get_ip_summary('146.246.166.225')
    ip_summary = summary.report()
    self.assertEqual(ip_summary, self.EXPECTED_IP_SUMMARY)

  def test_get_user_summary(self):
    """Test get_user_summary method."""
    aa = AuthAnalyzer(
        name='analyzer.auth', display_name='Auth Analyzer',
        description='Authentication analyzer')
    df = pd.read_csv('test_data/ssh_auth_data.csv')
    aa.set_dataframe(df)

    summary = aa.get_user_summary(domain='', username='gametogenesis')
    user_summary = summary.report()
    self.assertEqual(user_summary, self.EXPECTED_USER_SUMMARY)


if __name__ == '__main__':
  unittest.main()
