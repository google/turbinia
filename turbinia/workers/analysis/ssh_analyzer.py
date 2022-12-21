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
"""Task for analyzing Linux SSH analysis."""

import gzip
import hashlib
import logging
import os
import pandas as pd
import re

from datetime import datetime
from typing import Any, List

from turbinia import TurbiniaException

from turbinia.evidence import EvidenceState as state
from turbinia.evidence import ReportText
from turbinia.lib import text_formatter as fmt
from turbinia.lib.utils import extract_artifacts
from turbinia.workers import Priority
from turbinia.workers import TurbiniaTask
from turbinia.workers.analysis.auth import BruteForceAnalyzer

log = logging.getLogger('turbinia')

SSH_CONNECTION_PATTERN = {
    'accepted':
        re.compile(
            r'(\w+)\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+([^\s]+)\s+sshd\[(\d+)\]:\s+Accepted\s+([^\s]+)\s+for\s+([^\s]+)\s+from\s+([^\s]+)\s+port\s+(\d+)\s+ssh?'
        ),
    'failed':
        re.compile(
            r'(\w+)\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+([^\s]+)\s+sshd\[(\d+)\]:\s+Failed\s+([^\s]+)\s+for\s+([^\s]+)\s+from\s+([^\s]+)\s+port\s+(\d+)\s+ssh?'
        ),
    'invalid_user':
        re.compile(
            r'(\w+)\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+([^\s]+)\s+sshd\[(\d+)\]:\s+Failed\s+([^\s]+)\s+for\s+invalid\s+user\s+([^\s]+)\s+from\s+([^\s]+)\s+port\s+(\d+)\s+ssh'
        ),
    'disconnected':
        re.compile(
            r'(\w+)\s+(\d+)\s+(\d{2}:\d{2}:\d{2})\s+([^\s]+)\s+sshd\[(\d+)\]:\s+Disconnected\s+from\s+user\s+([^\s]+)\s+([^\s]+)\s+port\s+(\d+)'
        ),
}


class SSHEventData:
  """SSH authentication event."""

  def __init__(
      self, timestamp: int, date: str, time: str, hostname: str, pid: int,
      event_key: str, event_type: str, auth_method: str, auth_result: str,
      username: str, source_ip: str, source_port: int, source_hostname: str):
    self.timestamp = timestamp
    self.date = date
    self.time = time
    self.hostname = hostname
    self.pid = pid
    self.event_key = event_key
    self.event_type = event_type
    self.auth_method = auth_method
    self.auth_result = auth_result
    self.domain = ''  # Required for consistency with Windows
    self.username = username
    self.source_ip = source_ip
    self.source_port = source_port
    self.source_hostname = source_hostname
    self.session_id = None

  def calculate_session_id(self) -> None:
    hash_data = (
        f'{self.date}|{self.hostname}|{self.username}|{self.source_ip}|'
        f'{self.source_port}')

    h = hashlib.new('sha256')
    h.update(str.encode(hash_data))
    self.session_id = h.hexdigest()


class LinuxSSHAnalysisTask(TurbiniaTask):
  """Task to analyze Linux SSH authentication."""

  REQUIRED_STATES = [state.MOUNTED, state.CONTAINER_MOUNTED]

  TASK_CONFIG = {
      # This is the length of secons that the collected data will be processed.
      'ssh_analyzer_timeout': 600
  }

  # Log year validation
  # The minimum supported log year
  # NOTE: Python supports 1 as minimum year in datetime
  MIN_LOG_YEAR = 1970

  # Maximum supported valid log year
  # NOTE: Python datetime supports 9999 as maximum year
  MAX_LOG_YEAR = 9999

  def read_logs(self, log_dir: str) -> pd.DataFrame:
    """Read SSH authentication logs."""
    ssh_records = []

    for log_filename in os.listdir(log_dir):
      if not log_filename.startswith(
          'auth.log') and not log_filename.startswith('secure'):
        continue

      log_file = os.path.join(log_dir, log_filename)
      log.debug(f'Processing authentication log {log_file}')

      # Handle log archive
      if log_filename.endswith('.gz'):
        try:
          with gzip.open(log_file, 'rt', encoding='ISO-8859–1') as fh:
            log_data = fh.read()
            records = self.read_log_data(log_data, log_filename=log_filename)
            if records:
              ssh_records += records
        except gzip.BadGzipFile as e:
          log.error(f'Error opening a bad gzip file {str(e)}')
        finally:
          continue

      # Handle standard log file
      try:
        with open(log_file, 'r', encoding='ISO-8859–1') as fh:
          log_data = fh.read()
          records = self.read_log_data(log_data, log_filename=log_filename)
          if records:
            ssh_records += records
      except FileNotFoundError:
        log.error(f'{log_file} does not exist')
      finally:
        continue

    if not ssh_records:
      log.info(f'No SSH authenticaiton events in {log_dir}')
      return pd.DataFrame()
    log.info(
        f'Total number of SSH authentication events {len(ssh_records)} in {log_dir}.'
    )

    ssh_data = []
    for ssh_record in ssh_records:
      ssh_data.append(ssh_record.__dict__)
    df = pd.DataFrame(ssh_data)
    return df

  def read_log_data(
      self, data, log_filename: str, log_year: int = None) -> List:
    """ Parses SSH authentication log."""
    # check valid year is provided
    # If valid year isn't provided raise error
    if not log_year:
      current_date = datetime.now()
      log_year = current_date.year
      log.warning(
          f'Log year not provided in {log_filename} - assuming log year as'
          f' {log_year}')

    if log_year and (log_year < self.MIN_LOG_YEAR and
                     log_year > self.MAX_LOG_YEAR):
      raise TurbiniaException(
          f'Log year {log_year} is outside of acceptable range in {log_filename}'
      )

    ssh_records = []

    for key, value_re in SSH_CONNECTION_PATTERN.items():
      for line in value_re.findall(data):
        ssh_record = {}

        if key == 'accepted':
          event_type = 'authentication'
          auth_method = line[5]
          auth_result = 'success'
          username = line[6]
          source_ip = line[7]
          source_port = int(line[8])
        elif key == 'failed':
          event_type = 'authentication'
          auth_method = line[5]
          auth_result = 'failure'
          username = line[6]
          source_ip = line[7]
          source_port = int(line[8])
        elif key == 'invalid_user':
          event_type = 'authentication'
          auth_method = line[5]
          auth_result = 'failure'
          username = line[6]
          source_ip = line[7]
          source_port = int(line[8])
        elif key == 'disconnected':
          event_type = 'disconnection'
          auth_method = ''
          auth_result = 'disconnect'
          username = line[5]
          source_ip = line[6]
          source_port = int(line[7])

        # common log items
        dt_object = datetime.strptime(
            f'{line[0]} {line[1]}, {log_year} {line[2]}', '%b %d, %Y %H:%M:%S')
        timestamp = int(dt_object.strftime('%s'))
        date = f'{line[0]} {line[1]}'
        time = line[2]
        hostname = line[3]
        pid = int(line[4])

        ssh_event_data = SSHEventData(
            timestamp=timestamp, date=date, time=time, hostname=hostname,
            pid=pid, event_key=key, event_type=event_type,
            auth_method=auth_method, auth_result=auth_result, username=username,
            source_ip=source_ip, source_port=source_port, source_hostname='')
        ssh_event_data.calculate_session_id()
        ssh_records.append(ssh_event_data)

    log.info(
        f'Total number of SSH records {len(ssh_records)} in {log_filename}')
    return ssh_records

  def run(self, evidence, result):
    """Run the SSH Auth Analyzer worker.

    Args:
      evidence (Evidence object): The evidence of process
      result (TurbiniaTaskResult): The object to place task results into.
    Returns:
      TurbiniaTaskResult object.
    """

    # Output file and evidence
    output_file_name = 'linux_ssh_auth_analysis.txt'
    output_file_path = os.path.join(self.output_dir, output_file_name)
    output_evidence = ReportText(source_path=output_file_path)

    # Analyzer outputs
    analyzer_output_priority = Priority.LOW
    analyzer_output_summary = ''
    analyzer_output_report = ''
    output_summary_list = []
    output_report_list = []

    try:
      collected_artifacts = extract_artifacts(
          artifact_names=['LinuxAuthLogs'], disk_path=evidence.local_path,
          output_dir=self.output_dir, credentials=evidence.credentials)
    except TurbiniaException as exception:
      result.close(self, success=False, status=str(exception))
      return result

    log_dir = os.path.join(self.output_dir, 'var', 'log')
    result.log(f'Checking log directory {log_dir}')

    if not os.path.exists(log_dir):
      summary = f'Log directory path {log_dir} does not exist'
      result.close(self, success=False, status=summary)
      return result

    df = self.read_logs(log_dir=log_dir)
    if df.empty:
      summary = f'Empty dataframes from the logs in {log_dir}.'
      result.close(self, success=False, status=summary)
      return result

    # 01. Brute Force Analyzer
    bfa = BruteForceAnalyzer()
    bfa_result = bfa.run(df)

    if bfa_result:
      bfa_result_summary = bfa_result['result_summary']
      if bfa_result_summary:
        output_summary_list.append(bfa_result_summary)

      bfa_result_markdown = bfa_result['result_markdown']
      if bfa_result_markdown:
        output_report_list.append(bfa_result_markdown)
        # TODO(rmaskey): add attributes
    else:
      output_summary_list.append('No finding for brute force analysis')
      output_report_list.append('## Brute Force Analysis\n')
      output_report_list.append('- No findings for brute force analysis')

    # TODO(rmaskey): 02. Last X-Days Analyzer
    # TODO(rmaskey): 03. NICE Analyzer

    # 04. Handling result
    if output_summary_list:
      analyzer_output_summary = '. '.join(output_summary_list)
    else:
      analyzer_output_summary = 'No findings for SSH authenticaiton analyzer.'

    if output_report_list:
      analyzer_output_report = '\n'.join(output_report_list)
    else:
      analyzer_output_report = 'No finding for SSH authentication analyzer.'

    result.report_priority = analyzer_output_priority
    result.report_data = analyzer_output_report
    output_evidence.text_data = analyzer_output_report

    # 05. Write the report to the output file.
    with open(output_file_path, 'wb') as fh:
      fh.write(output_evidence.text_data.encode('utf-8'))

    # Add the resulting evidence to the result object.
    result.add_evidence(output_evidence, evidence.config)
    result.close(self, success=True, status=analyzer_output_summary)
    return result
