# -*- coding: utf-8 -*-
# Copyright 2022 Google Inc.
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
"""Base authentication analyzer"""

import logging
import pandas as pd

from datetime import datetime

log = logging.getLogger('turbinia')


class AuthAnalyzerError:
  """Exception class for authentication analyzer."""
  pass


class AuthSummaryData:
  """Authentication summary data."""

  def __init__(self):
    # Summary information for source_ip or username
    self.summary_type = None
    self.source_ip = ''
    self.domain = ''
    self.username = ''

    # The first time the source_ip or username observed in auth events.
    # This can be a successful or failed login event.
    self.first_seen = 0

    # The last time the source_ip or username was observed in auth events.
    # This can be a successful or failed login event.
    self.last_seen = 0

    # The first time the source_ip or username successfully login.
    self.first_auth_timestamp = 0
    self.first_auth_ip = ''
    self.first_auth_username = ''

    # The list of IP addresses that successfully authenticated to the system.
    # This is used when summary_type is username.
    self.success_source_ip_list = []
    self.success_username_list = []

    self.total_success_events = 0
    self.total_failed_events = 0

    # The total number of unique IP addresses observed in the log
    self.distinct_source_ip_count = 0
    self.distinct_username_count = 0

    self.top_source_ips = {}
    self.top_usernames = {}

  def report(self):
    return {
        'summary_type': self.summary_type,
        'source_ip': self.source_ip,
        'domain': self.domain,
        'username': self.username,
        'first_seen': self.first_seen,
        'last_seen': self.last_seen,
        'first_auth_timestamp': self.first_auth_timestamp,
        'first_auth_ip': self.first_auth_ip,
        'first_auth_username': self.first_auth_username,
        'total_success_events': self.total_success_events,
        'total_failed_events': self.total_failed_events,
        'success_source_ip_list': self.success_source_ip_list,
        'success_username_list': self.success_username_list,
        'distinct_source_ip_count': self.distinct_source_ip_count,
        'distinct_username_count': self.distinct_username_count,
        'top_source_ips': self.top_source_ips,
        'top_usernames': self.top_usernames,
    }