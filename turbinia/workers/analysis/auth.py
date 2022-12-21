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


class AuthAnalyzer:
  """Analyzer for authentication analysis.

  Attributes:
    name (str): Analyzer short name
    display_name (str): Display name of the analyzer
    description (str): Brief description about the analyzer
    df (pd.DataFrame): Authentication dataframe
  """

  REQUIRED_ATTRIBUTES = [
      'timestamp', 'event_type', 'auth_method', 'auth_result', 'hostname',
      'source_ip', 'source_port', 'source_hostname', 'domain', 'username',
      'session_id'
  ]

  def __init__(self, name: str, display_name: str, description: str) -> None:
    """Initialization of authentication analyzer.

    Args:
      name (str): Analyzer short name
      display_name (str): Analyzer display name
      description (str): Brief description of the analyzer
    """
    if not name:
      raise AuthAnalyzerError('analyzer name is required')
    if not display_name:
      raise AuthAnalyzerError('analyzer display name is required')

    self.name = name
    self.display_name = display_name
    self.description = description
    self.df = pd.DataFrame()

  def set_dataframe(self, df: pd.DataFrame) -> bool:
    """Sets dataframe.

    Args:
      df (pd.DataFrame): Authentication dataframe

    Returns:
      bool: Returns True if successfully set.
    """
    # We only want to proceed further if the panda dataframe
    # matches the required fields
    column_list = df.columns.tolist()
    if not self.check_required_fields(column_list):
      log.error(f'dataframe does not match required columns')
      return False

    df.fillna('', inplace=True)
    self.df = df
    self.df.sort_values('timestamp', ascending=True)
    return True

  def check_required_fields(self, fields: list) -> bool:
    """Checks the required fields in the data frame.

    Args:
      fields (list): List of columns name in dataframe

    Returns:
      bool: Returns true if required fields exist
    """

    for req_field in self.REQUIRED_ATTRIBUTES:
      if req_field not in fields:
        log.error(f'missing required field {req_field}')
        return False
    return True

  def get_ip_summary(self, source_ip: str) -> AuthSummaryData:
    """Source IP stats in the data frame.

    Args:
      source_ip (str): Source IP address whose summary will be generated.

    Returns:
      dict: IP summary information as a dictionary
    """

    if self.df.empty:
      log.info(f'source dataframe is empty')
      return {}
    df = self.df

    df1 = df[df['source_ip'] == source_ip]
    if df1.empty:
      log.info(f'{source_ip}: no data for source ip')
      return {}
    return self.get_auth_summary(
        df1=df1, summary_type='source_ip', value=source_ip)

  def get_user_summary(self, domain: str, username: str) -> AuthSummaryData:
    """Username stats in the dataframe.

    Args:
      domain (str): Filter dataframe using domain
      username (str): Filter dataframe using username

    Returns:
      dict: user summary information as dictionary
    """
    if self.df.empty:
      log.info(f'source dataframe is empty')
      return {}
    df = self.df

    df1 = df[(df['domain'] == domain) & (df['username'] == username)]
    if df1.empty:
      log.info(f'user summary dataframe is empty')
      return {}

    df1.sort_values(by='timestamp', ascending=True)

    useraccount = self.to_useraccount(domain, username)
    return self.get_auth_summary(
        df1=df1, summary_type='username', value=useraccount)

  def get_auth_summary(
      self, df1: pd.DataFrame, summary_type: str,
      value: str) -> AuthSummaryData:
    df1.sort_values(by='timestamp', ascending=True)

    summary = AuthSummaryData()

    if summary_type == 'source_ip':
      summary.summary_type = 'source_ip'
      summary.source_ip = value
    elif summary_type == 'username':
      domain, username = self.from_useraccount(value)
      summary.summary_type = 'username'
      summary.domain = domain
      summary.username = username
    else:
      log.error(f'unsupported summary_type value {summary_type}')
      return summary

    # First and last time the brute forcing IP address was observed
    summary.first_seen = int(df1.iloc[0]['timestamp'])
    summary.last_seen = int(df1.iloc[-1]['timestamp'])

    # The list of successful source_ip addresses and usernames.
    #summary['usernames'] = list(
    #    set(df1[df1['auth_result'] == 'success']['username'].to_list()))
    summary.success_source_ip_list = list(
        set(df1[df1['auth_result'] == 'success']['source_ip'].to_list()))
    summary.success_username_list = list(
        set(df1[df1['auth_result'] == 'success']['username'].to_list()))

    # Authentication events
    df_success = df1[df1['auth_result'] == 'success']
    if not df_success.empty:
      summary.first_auth_timestamp = int(df_success.iloc[0]['timestamp'])
      summary.first_auth_ip = df_success.iloc[0]['source_ip']
      summary.first_auth_username = df_success.iloc[0]['username']

    # Total number of successful and failed login events
    summary.total_success_events = len(df_success.index)
    df_failure = df1[df1['auth_result'] == 'failure']
    summary.total_failed_events = len(df_failure.index)

    # Total number of unique ip and username attempted
    #summary['unique_username_count'] = len(df1['username'].unique())
    summary.distinct_source_ip_count = len(df1['source_ip'].unique())
    summary.distinct_username_count = len(df1['username'].unique())

    # Top 10 ip and username attempted
    #summary['top_usernames'] = df1.groupby(
    #    by='username')['timestamp'].nunique().nlargest(10).to_dict()
    summary.top_source_ips = df1.groupby(
        by='source_ip')['timestamp'].nunique().nlargest(10).to_dict()
    summary.top_usernames = df1.groupby(
        by='username')['timestamp'].nunique().nlargest(10).to_dict()

    return summary

  def to_useraccount(self, domain: str, username: str) -> str:
    """Convert domain and username to useraccount."""

    if not username or username.lower() == 'nan':
      return username
    return f'{domain}\\{username}'

  def from_useraccount(self, useraccount: str):
    """Split useraccount into domain and username."""

    if not '\\' in useraccount:
      return '', useraccount

    val = useraccount.split('\\')
    try:
      domain = val[0].strip()
      username = val[1].strip()
      return domain, username
    except ValueError:
      return '', username

  def human_timestamp(self, timestamp: int) -> str:
    """Convert epoch timestamp to humand readable date/time."""
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

  def get_login_session(
      self, source_ip: str, domain: str, username: str,
      session_id: str) -> dict:
    """Get loging session details."""
    login_session = {
        'source_ip': source_ip,
        'domain': domain,
        'username': username,
        'session_id': session_id,
        'login_timestamp': 0,
        'logout_timestamp': 0,
        'session_duration': 0,
    }

    if self.df.empty:
      log.debug('source dataframe is empty')
      return login_session
    df = self.df
    try:
      df_session = df[(df['source_ip'] == source_ip)
                      & (df['username'] == username) &
                      (df['session_id'] == session_id)]
      login_ts = int(
          df_session[df_session['auth_result'] == 'success'].iloc[0]
          ['timestamp'])
      logout_ts = int(
          df_session[df_session['event_type'] == 'disconnection'].iloc[0]
          ['timestamp'])
      session_duration = logout_ts - login_ts
      login_session['login_timestamp'] = login_ts
      login_session['logout_timestamp'] = logout_ts
      login_session['session_duration'] = session_duration
    except:
      log.error(f'failed to calcuate session duration')
    finally:
      return login_session
