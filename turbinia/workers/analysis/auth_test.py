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
import os
import pandas as pd
import unittest

from turbinia.workers.analysis.auth import AuthAnalyzer
from turbinia.workers.analysis.auth import BruteForceAnalyzer
from turbinia.workers.analysis.ssh_analyzer import LinuxSSHAnalysisTask

log = logging.getLogger('turbinia')
log.setLevel(logging.DEBUG)


def load_test_dataframe() -> pd.DataFrame:
  log_file = 'test_data/secure'
  if not os.path.exists(log_file):
    return pd.DataFrame()

  with open(log_file, 'r', encoding='utf-8') as fh:
    data = fh.read()
  analyzer = LinuxSSHAnalysisTask()
  ssh_records = analyzer.read_log_data(data, log_file, log_year=2022)

  records = []
  for ssh_record in ssh_records:
    records.append(ssh_record.__dict__)
  return pd.DataFrame(records)


class TestAuthAnalyzer(unittest.TestCase):
  """Test class for AuthAnalyzer"""

  EXPECTED_IP_SUMMARY = {
      'summary_type': 'source_ip',
      'source_ip': '192.168.140.67',
      'domain': '',
      'username': '',
      'first_seen': 1664739900,
      'last_seen': 1665252640,
      'first_auth_timestamp': 1665252633,
      'first_auth_ip': '192.168.140.67',
      'first_auth_username': 'admin',
      'success_source_ip_list': ['192.168.140.67'],
      'success_username_list': ['admin'],
      'total_success_events': 1,
      'total_failed_events': 27594,
      'distinct_source_ip_count': 1,
      'distinct_username_count': 2,
      'top_source_ips': {
          '192.168.140.67': 5204
      },
      'top_usernames': {
          'root': 5173,
          'admin': 31
      }
  }

  EXPECTED_USER_SUMMARY = {
      'summary_type': 'username',
      'source_ip': '',
      'domain': '',
      'username': 'kadmin',
      'first_seen': 1664739446,
      'last_seen': 1665252676,
      'first_auth_timestamp': 1664739446,
      'first_auth_ip': '172.30.151.71',
      'first_auth_username': 'kadmin',
      'success_source_ip_list': ['172.30.151.91', '172.30.151.71'],
      'success_username_list': ['kadmin'],
      'total_success_events': 2,
      'total_failed_events': 0,
      'distinct_source_ip_count': 2,
      'distinct_username_count': 1,
      'top_source_ips': {
          '172.30.151.71': 1,
          '172.30.151.91': 1
      },
      'top_usernames': {
          'kadmin': 2
      }
  }

  EMPTY_LOGIN_SESSION = {
      'source_ip': '',
      'domain': '',
      'username': '',
      'session_id': '',
      'login_timestamp': 0,
      'logout_timestamp': 0,
      'session_duration': 0,
  }

  EXPECTED_LOGIN_SESSION = {
      'source_ip':
          '192.168.140.67',
      'domain':
          '',
      'username':
          'admin',
      'session_id':
          '7b45adc5a3d14261800c1782719f647b81b3b8013836f30893f23202b592e000',
      'login_timestamp':
          1665252633,
      'logout_timestamp':
          1665252640,
      'session_duration':
          7
  }

  def setUp(self):
    self.analyzer = AuthAnalyzer(
        name='analyzer.auth', display_name='Auth Analyzer',
        description='Authentication analyzer')

  def test_check_required_fields(self):
    """Test check_required_fields method."""
    # Test 1: Does not meet required fields.
    missing_fields = [
        'timestamp', 'event_type', 'auth_method', 'auth_result', 'hostname',
        'source_ip', 'source_port', 'source_hostname', 'domain', 'username'
    ]
    self.assertFalse(self.analyzer.check_required_fields(missing_fields))

    # Test 2: Meets required fields
    valid_fields = [
        'timestamp', 'event_type', 'auth_method', 'auth_result', 'hostname',
        'source_ip', 'source_port', 'source_hostname', 'domain', 'username',
        'session_id'
    ]
    self.assertTrue(self.analyzer.check_required_fields(valid_fields))

  def test_get_ip_summary(self):
    """Test get_ip_summary method."""
    # Test 1: Empty dataframe.
    name = 'get_ip_summary'
    print(f'[{name}] Test 1: Empty dataframe')
    df = pd.DataFrame()
    self.analyzer.set_dataframe(df)
    summary = self.analyzer.get_ip_summary('100.100.100.100')
    self.assertIsNone(summary)

    # Common dataframe for the rest of the unit tests
    df = pd.read_csv('test_data/secure.csv')
    self.analyzer.set_dataframe(df)

    # Test 2: Checking for non-existent source_ip
    print(f'[{name}] Test 2: Non-existent IP address 100.100.100.100')
    summary = self.analyzer.get_ip_summary('100.100.100.100')
    self.assertIsNone(summary)

    # Test 3: Checking a valid source_ip
    print(f'[{name}] Test 3: Checking for valid IP 192.168.140.67')
    summary = self.analyzer.get_ip_summary('192.168.140.67')
    ip_summary = summary.report()
    self.assertEqual(ip_summary, self.EXPECTED_IP_SUMMARY)

  def test_get_user_summary(self):
    """Test get_user_summary method."""
    fname = 'get_user_summary'

    # Test 1: Empty datafram
    print(f'[{fname}] Test 1: Empty dataframe')
    df = pd.DataFrame()
    self.analyzer.set_dataframe(df)
    summary = self.analyzer.get_user_summary(
        domain='', username='gametogenesis')
    self.assertIsNone(summary)

    # Dataframe for the rest of the tests
    df = pd.read_csv('test_data/secure.csv')
    self.analyzer.set_dataframe(df)

    # Test 2: Non-existent username
    print(f'[{fname}] Test 2: Checking non-existent username supermario')
    summary = self.analyzer.get_user_summary(domain='', username='supermario')
    self.assertIsNone(summary)

    # Test 3: Valid username
    print(f'[{fname}] Test 3: Checking for valid username kadmin')
    summary = self.analyzer.get_user_summary(domain='', username='kadmin')
    self.assertIsNotNone(summary)
    user_summary = summary.__dict__
    print(user_summary)
    self.assertEqual(self.EXPECTED_USER_SUMMARY, user_summary)

  def test_get_auth_summary(self):
    """Test get_auth_summary method."""
    fname = 'get_auth_summary'

    # Test 1: Empty dataframe
    print(f'[{fname}] Test 1: Empty dataframe')
    df = pd.DataFrame()
    result = self.analyzer.set_dataframe(df)
    self.assertFalse(result)
    summary = self.analyzer.get_auth_summary(df, 'source_ip', '100.100.100.100')
    self.assertIsNone(summary)

    # Dataframe for the rest of the tests
    df = pd.read_csv('test_data/auth.log.csv')
    self.analyzer.set_dataframe(df)

    # Test 2: Invalid summary_type
    print(f'[{fname}] Test 2: Invalid summary_type value')
    summary = self.analyzer.get_auth_summary(df, 'source_port', 54321)
    self.assertIsNone(summary)

    # Test 3: Valid summary_type source_ip
    print(f'[{fname}] Test 3: Valid summary_type source_ip')
    summary = self.analyzer.get_auth_summary(df, 'source_ip', '193.68.140.67')
    self.assertIsNotNone(summary)

    # Test 4: Valid summary_type username
    print(f'[{fname}] Test 4: Valid source_type username')
    summary = self.analyzer.get_auth_summary(df, 'username', 'kadmin')
    self.assertIsNotNone(summary)

  def test_to_useraccount(self):
    """Test to_useraccount method."""

    # Test 1: Empty domain and username
    useraccount = self.analyzer.to_useraccount(domain='', username='')
    self.assertEqual(useraccount, '')

    # Test 2: Non-empty domain and username
    useraccount = self.analyzer.to_useraccount(
        domain='example', username='admin')
    self.assertEqual(useraccount, 'example\\admin')

  def test_from_useraccount(self):
    """Test from_useraccount method."""

    # Test 1: Empty useraccount
    domain, username = self.analyzer.from_useraccount('')
    self.assertEqual(domain, '')
    self.assertEqual(username, '')

    # Test 2: Empty domain
    domain, username = self.analyzer.from_useraccount('admin')
    self.assertEqual(domain, '')
    self.assertEqual(username, 'admin')

    # Test 3: Domain and username
    domain, username = self.analyzer.from_useraccount('example\\admin')
    self.assertEqual(domain, 'example')
    self.assertEqual(username, 'admin')

  def test_human_timestamp(self):
    """Test human_timestamp method."""
    dtstring = self.analyzer.human_timestamp(0)
    self.assertEqual(dtstring, '1970-01-01 00:00:00')

    dtstring = self.analyzer.human_timestamp(1675915532)
    self.assertEqual(dtstring, '2023-02-09 04:05:32')

  def test_get_login_session(self):
    """Test get_login_session method."""
    fname = 'get_login_session'

    # Test 1: Empty dataframe
    print(f'[{fname}] Test 1: Empty dataframe and empty parameters')
    df = pd.DataFrame()
    self.analyzer.set_dataframe(df)
    login_session = self.analyzer.get_login_session('', '', '', '')
    self.assertIsNone(login_session)

    # Dataframe for the rest of the tests
    df = pd.read_csv('test_data/secure.csv')
    self.analyzer.set_dataframe(df)

    # Test 2: Checking for non-existent parameter values
    print(f'[{fname}] Test 2: Non-existent value of the parameters')
    login_session = self.analyzer.get_login_session(
        source_ip='100.100.100.100', domain='', username='gametogenesis',
        session_id='kurbtwhfwq')
    self.assertIsNone(login_session)

    # Test 3: Checking a valid session
    print(f'[{fname}] Test 3: Checking for valid session')
    login_session = self.analyzer.get_login_session(
        source_ip='192.168.140.67', domain='', username='admin',
        session_id='7b45adc5a3d14261800c1782719f647b81b3b8013836f30893f23202b5'
        '92e000')
    self.assertEqual(self.EXPECTED_LOGIN_SESSION, login_session)


class TestBruteForceAnalyzer(unittest.TestCase):
  """Test class for BruteForceAnalyzer"""

  EXPECTED_LOG_ANALYSIS_OUTPUT = {
      'source_ip':
          '192.168.140.67',
      'brute_force_logins': [{
          'source_ip': '192.168.140.67',
          'domain': '',
          'username': 'admin',
          'session_id':
              '7b45adc5a3d14261800c1782719f647b81b3b8013836f30893f23202b'
              '592e000',
          'login_timestamp': 1665252633,
          'logout_timestamp': 1665252640,
          'session_duration': 7
      }],
      'ip_summaries': [{
          'summary_type': 'source_ip',
          'source_ip': '192.168.140.67',
          'domain': '',
          'username': '',
          'first_seen': 1664739900,
          'last_seen': 1665252640,
          'first_auth_timestamp': 1665252633,
          'first_auth_ip': '192.168.140.67',
          'first_auth_username': 'admin',
          'total_success_events': 1,
          'total_failed_events': 27594,
          'success_source_ip_list': ['192.168.140.67'],
          'success_username_list': ['admin'],
          'distinct_source_ip_count': 1,
          'distinct_username_count': 2,
          'top_source_ips': {
              '192.168.140.67': 5204
          },
          'top_usernames': {
              'root': 5173,
              'admin': 31
          }
      }],
      'user_summaries': [{
          'summary_type': 'username',
          'source_ip': '',
          'domain': '',
          'username': 'admin',
          'first_seen': 1665252582,
          'last_seen': 1665252640,
          'first_auth_timestamp': 1665252633,
          'first_auth_ip': '192.168.140.67',
          'first_auth_username': 'admin',
          'total_success_events': 1,
          'total_failed_events': 228,
          'success_source_ip_list': ['192.168.140.67'],
          'success_username_list': ['admin'],
          'distinct_source_ip_count': 1,
          'distinct_username_count': 1,
          'top_source_ips': {
              '192.168.140.67': 31
          },
          'top_usernames': {
              'admin': 31
          }
      }]
  }

  EXPECTED_RUN_OUTPUT = {
      'platform':
          'turbinia',
      'analyzer_identifier':
          'bruteforce.auth.analyzer',
      'analyzer_name':
          'Brute Force Analyzer',
      'result_status':
          'success',
      'dfiq_question_id':
          '',
      'dfiq_question_conclusion':
          '',
      'result_priority':
          'MEDIUM',
      'result_summary':
          'Brute force from 1 IP addresses',
      'result_markdown':
          '## Brute Force Analysis\n\n### Brute Force from 192.168.140.67\n\n-'
          ' Successful brute force from 192.168.140.67 as admin at 2022-10-08 '
          '18:10:33 (duration=7)\n\n#### IP Summaries\n\n- Source IP: 192.168.'
          '140.67\n- Brute forcing IP first seen: 2022-10-02 19:45:00\n- Brute'
          ' forcing IP last seen: 2022-10-08 18:10:40\n- First successful '
          'login for brute forcing IP\n    - IP: 192.168.140.67\n    - Login'
          ' timestamp: 2022-10-08 18:10:33\n    - Username: admin\n- Total '
          'successful login from IP: 1\n- Total failed login attempts: 27594'
          '\n- IP addresses that successfully logged in: 192.168.140.67\n- '
          'Usernames that successfully logged in: admin\n- Total number of '
          'unique username attempted: 2\n- Top 10 username attempted\n    - '
          'root: 5173\n    - admin: 31\n',
      'references': [],
      'attributes': [{
          'source_ip':
              '192.168.140.67',
          'brute_force_logins': [{
              'source_ip': '192.168.140.67',
              'domain': '',
              'username': 'admin',
              'session_id':
                  '7b45adc5a3d14261800c1782719f647b81b3b8013836f30893f23202b'
                  '592e000',
              'login_timestamp': 1665252633,
              'logout_timestamp': 1665252640,
              'session_duration': 7
          }],
          'ip_summaries': [{
              'summary_type': 'source_ip',
              'source_ip': '192.168.140.67',
              'domain': '',
              'username': '',
              'first_seen': 1664739900,
              'last_seen': 1665252640,
              'first_auth_timestamp': 1665252633,
              'first_auth_ip': '192.168.140.67',
              'first_auth_username': 'admin',
              'total_success_events': 1,
              'total_failed_events': 27594,
              'success_source_ip_list': ['192.168.140.67'],
              'success_username_list': ['admin'],
              'distinct_source_ip_count': 1,
              'distinct_username_count': 2,
              'top_source_ips': {
                  '192.168.140.67': 5204
              },
              'top_usernames': {
                  'root': 5173,
                  'admin': 31
              }
          }],
          'user_summaries': [{
              'summary_type': 'username',
              'source_ip': '',
              'domain': '',
              'username': 'admin',
              'first_seen': 1665252582,
              'last_seen': 1665252640,
              'first_auth_timestamp': 1665252633,
              'first_auth_ip': '192.168.140.67',
              'first_auth_username': 'admin',
              'total_success_events': 1,
              'total_failed_events': 228,
              'success_source_ip_list': ['192.168.140.67'],
              'success_username_list': ['admin'],
              'distinct_source_ip_count': 1,
              'distinct_username_count': 1,
              'top_source_ips': {
                  '192.168.140.67': 31
              },
              'top_usernames': {
                  'admin': 31
              }
          }]
      }]
  }

  def setUp(self):
    self.analyzer = BruteForceAnalyzer()

  def test_login_analysis(self):
    """Test login_analysis method."""
    fname = 'login_analysis'

    # Test 1: Empty dataframe
    print(f'[{fname}] Test 1: Empty dataframe')
    df = pd.DataFrame()
    self.analyzer.set_dataframe(df)
    output = self.analyzer.login_analysis('100.100.100.100')
    self.assertIsNone(output)

    # Common dataframe used for unit tests
    df = pd.read_csv('test_data/secure.csv')
    self.analyzer.set_dataframe(df)

    # Test 2: Login analysis with empty source_ip
    print(f'[{fname}] Test 2: Empty source_ip in login_analysis')
    output = self.analyzer.login_analysis(source_ip='')
    self.assertIsNone(output)

    # Test 3: Log analysis for non-existent IP address
    print(f'[{fname}] Test 3: Log analysis for non-existent IP address')
    output = self.analyzer.login_analysis(source_ip='100.100.100.100')
    self.assertIsNone(output)

    # Test 4: Login analysis for unsuccessful IP address
    print(f'[{fname}] Test 4: Login analysis for unsuccessful IP address')
    output = self.analyzer.login_analysis(source_ip='172.30.151.91')
    self.assertIsNone(output)

    # Test 5: Login analysis for successful IP address
    print(f'[{fname}] Test 5: Login analysis for successful IP address')
    output = self.analyzer.login_analysis(source_ip='192.168.140.67')
    self.assertEqual(self.EXPECTED_LOG_ANALYSIS_OUTPUT, output)

  def test_run(self):
    """Test run method."""

    df = load_test_dataframe()
    output = self.analyzer.run(df)
    self.assertEqual(self.EXPECTED_RUN_OUTPUT, output)


if __name__ == '__main__':
  unittest.main()
