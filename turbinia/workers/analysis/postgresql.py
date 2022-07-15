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
"""Task for analysing PostgreSQL server."""

import os
import re

from collections import namedtuple

from turbinia import TurbiniaException

from turbinia.evidence import EvidenceState as state
from turbinia.evidence import ReportText
from turbinia.lib import text_formatter as fmt
from turbinia.lib.utils import extract_files
from turbinia.lib.utils import extract_custom_artifacts
from turbinia.workers import Priority
from turbinia.workers import TurbiniaTask

_PG_CONF_NAME = 'postgresql.conf'
_PG_HBA_NAME = 'pg_hba.conf'
_PASSWD_FILE = 'passwd'
_PG_ACCOUNT = 'postgres'
_BASH_HISTORY = '.bash_history'
_PSQL_HISTORY = '.psql_history'

_POSTGRESQL_ARTIFACTS = """---
name: PostgreSQLConfigurationFiles
doc: PostgreSQL configuration files.
sources:
- type: FILE
  attributes:
    paths:
    - '/etc/postgresql/*/main/postgresql.conf'
    - '/etc/postgresql/*/main/pg_hba.conf'
    - '/etc/postgresql/*/main/pg_ident.conf'
    - '/var/lib/pgsql/postgresql.conf'
    - '/var/lib/pgsql/pg_hba.conf'
    - '/var/lib/pgsql/pg_ident.conf'
    - '/var/lib/pgsql/data/postgresql.conf'
    - '/var/lib/pgsql/data/pg_hba.conf'
    - '/var/lib/pgsql/data/pg_ident.conf'
supported_os: [Linux]
urls:
- 'https://www.postgresql.org/docs/current/runtime-config-file-locations.html'
- 'https://docs.fedoraproject.org/en-US/quick-docs/postgresql/'
---
name: PostgreSQLDataDirectory
doc: PostgreSQL data directory.
sources:
- type: FILE
  attributes:
    paths:
    - '/var/lib/postgresql/*/main/*/*'
    - '/var/lib/pgsql/data/*'
    - '/var/lib/pgsql/data-old/*'
    - '/var/lib/pgsql/*/*'
supported_os: [Linux]
urls:
- 'https://www.postgresql.org/docs/current/storage-file-layout.html'
- 'https://docs.fedoraproject.org/en-US/quick-docs/postgresql/'
---
name: PostgreSQLLogFiles
doc: PostgreSQL log files.
sources:
- type: FILE
  attributes:
    paths:
    - '/var/log/postgresql/postgresql.log*'
    - '/var/log/postgresql/postgresql.csv*'
    - '/var/log/postgresql/postgresql-*.log*'
    - '/var/log/postgresql/postgresql-*.csv*'
    - '/var/log/postgresql/postgresql-*-*.log*'
    - '/var/log/postgresql/postgresql-*-*.csv*'
    - '/var/lib/pgsql/data/log/postgresql.log*'
    - '/var/lib/pgsql/data/log/postgresql.csv*'
    - '/var/lib/pgsql/data/log/postgresql-*.log*'
    - '/var/lib/pgsql/data/log/postgresql-*.csv*'
    - '/var/lib/pgsql/data/log/postgresql-*-*.log*'
    - '/var/lib/pgsql/data/log/postgresql-*-*.csv*'
supported_os: [Linux]
urls: ['https://www.postgresql.org/docs/14/runtime-config-logging.html']
"""

# Potentially suspicious commands to look on a `.bash_history` and
# `.psql_history`
SqlCommand = namedtuple('SqlCommand', ['name', 'priority', 'pattern'])
sqlcommands = [
  SqlCommand(name='select_all', priority=Priority.LOW,
      pattern=re.compile(r'select\s*\*\s*from\s*.*', re.IGNORECASE)),
  SqlCommand(name='pg_dump', priority=Priority.LOW,
      pattern=re.compile(r'pg_dump\s*.*', re.IGNORECASE)),
  SqlCommand(name='select_count', priority=Priority.LOW,
      pattern=re.compile(r'select\s*count\(\S+\)\s*from\s*.*', re.IGNORECASE)),
]


class PostgreSQLAnalysisTask(TurbiniaTask):
  """Task to analyze PostgreSQL server."""

  REQUIRED_STATES = [state.MOUNTED, state.CONTAINER_MOUNTED]

  def run(self, evidence, result):
    """Run the PostgreSQL server analyzer.

    Args:
      evidence (Evidence): The evidence to process.
      result (TurbiniaTaskResult): The object to place task result.

    Returns:
      TurbiniaTaskResult
    """

    # store the resulting output file
    output_file_name = 'postgresql_analysis.md'
    output_file_path = os.path.join(self.output_dir, output_file_name)

    # type of evidence output
    output_evidence = ReportText(source_path=output_file_path)

    # add logs for processing and debug context
    result.log(f'Evidence source path {evidence.source_path}')
    result.log(f'Evidence local path {evidence.local_path}')
    result.log(f'Evidence mount path {evidence.mount_path}')

    #
    # PostgreSQL analysis modules
    #
    # Run multiple analysis modules and append each module findings to
    # reports.
    #
    # Module findings MUST be added to reports as Tuple with follwoing details.
    # Named tuple (
    #   name(str): Name of module or artifact processed
    #   artifact_path(str): Path of the artifact on evidence disk
    #   priority(int): Module summary priority
    #   summary(str): Summay of a module's findings
    #   report(str): Detailed findings of a module
    #   )
    ModuleReport = namedtuple('ModuleReport',
        ['name', 'artifact_path', 'priority', 'summary', 'report'])
    reports = []

    # Module: PostgreSQL Configuration Analysis
    # 1.1. find postgresql.conf and copy to artifact directory
    try:
      artifact_locations, err = self._collect_artifact(
          _PG_CONF_NAME, evidence)
      if err:
        result.log(err)
        result.close(self, success=True, status='No PostgreSQL config found')
        return result

      if not artifact_locations:
        result.close(self, success=False,
            status='Error setting artifact location')

      result.log('postgresql.conf location {0:s}'.format(
          ','.join(artifact_locations)))
    except TurbiniaException as e:
      result.close(self, success=False,
          status='Error retrieving PostgreSQL config: {0:s}'.format(str(e)))
      return result

    # 1.2. analyze postgresql.conf
    # assumptions: possibilities of multiple postgresql.conf
    for artifact_location in artifact_locations:
      result.log(f'Processing postgresql.conf: {artifact_location}')
      config_data = read_file(artifact_location)

      # artifact_path holds the path on the evidece disk
      artifact_disk_path = self._get_artifact_disk_path(artifact_location)

      (report, priority, summary), err = self._analyze_postgresql_config(
          config_data)
      if err:
        result.log(err)

      reports.append(ModuleReport(name='Server Configuration: postgresql.conf',
          artifact_path=artifact_disk_path, priority=priority,
          summary=summary, report=report))

    # 2. Module: PostgreSQL Client Authentication Analysis
    # 2.1. find pg_hba.conf
    try:
      artifact_locations, err = self._collect_artifact(
          _PG_HBA_NAME, evidence)
      if err:
        result.log(err)
        result.close(self, success=False, status='No pg_hba.conf found')
        return result

      if not artifact_locations:
        result.close(self, success=False,
            status='Error setting artifact location')
      result.log('pg_hba.conf location {0:s}'.format(
          ', '.join(artifact_locations)))
    except TurbiniaException as e:
      result.close(self, success=False,
          status='Error retrieving client authentication config: {0:s}'.format(
          str(e)))
      return result

    for artifact_location in artifact_locations:
      result.log(f'Processing pg_hba.conf: {artifact_location}')
      artifact_disk_path = self._get_artifact_disk_path(artifact_location)

      config_data = read_file(artifact_location)
      (report, priority, summary) = self._analyze_pg_hba_config(config_data,
          result)

      reports.append(ModuleReport(name='Client Authentication: pg_hba.conf',
          artifact_path=artifact_disk_path, priority=priority,
          summary=summary, report=report))

    # Module: Postgres Linux User Analysis
    # 3. Find /etc/passwd and analyze `postgres` account
    artifact_locations, err = self._collect_artifact(_PASSWD_FILE, evidence)
    if err:
      result.log(err)
    else:
      for artifact_location in artifact_locations:
        # we only want to process /etc/passwd
        if '/etc/passwd' not in artifact_location:
          result.log(f'Ignore passwd file {artifact_location}')
          continue

        result.log(f'Processing passwd: {artifact_location}')
        artifact_disk_path = self._get_artifact_disk_path(artifact_location)

        data = read_file(artifact_location)
        (report, priority, summary) = self._analyze_linux_postgres_account(data)

        reports.append(ModuleReport(name='Linux Account: postgres',
            artifact_path=artifact_disk_path, priority=priority,
            summary=summary, report=report))

    # Module: User Bash History Analysis
    # It includes all user bash history including postgres user account.
    # 4. Find and analyze .bash_history
    artifact_locations, err = self._collect_artifact(_BASH_HISTORY, evidence)
    if err:
      result.log(f'Error retrieving {_BASH_HISTORY}: {err}')
    else:
      for artifact_location in artifact_locations:
        result.log(f'Processing .bash_history: {artifact_location}')
        artifact_disk_path = self._get_artifact_disk_path(artifact_location)
        username = artifact_location.split('/')[-2]

        data = read_file(artifact_location)
        (report, priority, summary) = self._analyze_shell_history(data)

        reports.append(ModuleReport(
            name=f'Bash History for {username}: {_BASH_HISTORY}',
            artifact_path=artifact_disk_path, priority=priority,
            summary=summary, report=report))

    # Module: PostgreSQL Client History
    # 5. Find and analyze .pgsql_history
    artifact_locations, err = self._collect_artifact(_PSQL_HISTORY, evidence)
    if err:
      result.log(f'Error retrieving {_PSQL_HISTORY}: {err}')
    else:
      for artifact_location in artifact_locations:
        result.log(f'Processing {_PSQL_HISTORY}: {artifact_location}')
        artifact_disk_path = self._get_artifact_disk_path(artifact_location)
        username = artifact_location.split('/')[-2]

        data = read_file(artifact_location)
        (report, priority, summary) = self._analyze_shell_history(data)

        reports.append(ModuleReport(
            name=f'PSQL Client History for {username}: {_PSQL_HISTORY}',
            artifact_path=artifact_disk_path, priority=priority,
            summary=summary, report=report))

    # Module: PostgreSQL Database User Analysis
    # 6. Find and analyze PostgreSQL database user analysis.
    #
    # Note: This analysis is sipped as this analysis is covered by
    # PostgresAccountAnalysisJob

    # Module: PostgreSQL Log Analysis
    # 6. Find and analyze PostgreSQL server logs
    artifact_locations = self._collect_log_artifacts(evidence)
    if not artifact_locations:
      result.log('PostgreSQL log files not found')
    else:
      for artifact_location in artifact_locations:
        result.log(f'Processing log {artifact_location}')
        artifact_disk_path = self._get_artifact_disk_path(artifact_location)

        data = read_file(artifact_location)
        (report, priority, summary) = self._analyze_postgresql_log(data)

        reports.append(ModuleReport(name='PostgreSQL Log',
            artifact_path=artifact_disk_path, priority=priority,
            summary=summary, report=report))

    # Generate final report based on module reports
    # x. Generate report
    final_report, final_priority, final_summary = self._generate_report(reports)

    output_evidence.text_data = final_report
    result.report_data = final_report
    result.report_priority = final_priority

    # write the report to the output file
    with open(output_file_path, 'wb') as fh:
      fh.write(output_evidence.text_data.encode('utf8'))
      fh.write('\n'.encode('utf8'))

    # add evidence to result object
    result.add_evidence(output_evidence, evidence.config)
    result.close(self, success=True, status=final_summary)

    return result

  def _collect_artifact(self, filename, evidence):
    """Extract artifacts using image_export.

    Args:
      filename (str): Name of the file to be collected
      evidence (Evidence): Evidence to be processed

    Returns:
      location (list(str)): List of artifact paths
      err (str): Error message
    """
    try:
      collected_artifacts = extract_files(
          file_name=filename,
          disk_path=evidence.local_path,
          output_dir=os.path.join(self.output_dir, 'artifacts'),
          credentials=evidence.credentials)
    except TurbiniaException as e:
      raise TurbiniaException(
          'artifact extraction failed: {0:s}'.format(str(e))) from e

    artifacts = []

    for collected_artifact in collected_artifacts:
      location = os.path.dirname(collected_artifact)
      for dirpath, _, filenames in os.walk(location):
        if filename not in filenames:
          continue
        artifacts.append(os.path.join(dirpath, filename))

    artifacts = list(set(artifacts))
    return artifacts, None

  def _get_artifact_disk_path(self, collected_artifact_path):
    """Returns the artifact disk path.

    Args:
      collected_artifact_path (str): Collected artifact output path

    Returns:
      artifact_disk_path (str): Absolute path of artifact on disk
    """
    artifacts_path = os.path.join(self.output_dir, 'artifacts')
    return collected_artifact_path[len(artifacts_path):]

  def _analyze_postgresql_config(self, data):
    """Analyze extracted postgresql.conf key-value.

    Args:
      data (str): Content of postgresql.conf

    Returns:
      Tuple(
        module_report (str): Module report
        module_priority (int): The priority of module summary
        module_summary (str): A summary of the report (used for task status)
      )
    """
    if not data:
      return ('', Priority.LOW, 'Empty configuration file')

    module_summary = 'No suspicious findings'
    module_priority = Priority.LOW
    module_report = ''

    report = []
    err = ''

    commented_line_re = re.compile(r'^\s*#.*')

    ConfigPattern = namedtuple('ConfigPattern', ['name', 'priority', 'pattern'])
    config_pattern = [
      ConfigPattern(name='data_directory', priority=Priority.LOW,
          pattern=re.compile(r'data_directory\s*=\s*\'([^\']+)\'')),
      ConfigPattern(name='hba_file', priority=Priority.LOW,
          pattern=re.compile(r'hba_file\s*=\s*\'([^\']+)\'')),
      ConfigPattern(name='ident_file', priority=Priority.LOW,
          pattern=re.compile(r'ident_file\s*=\s*\'([^\']+)\'')),
      ConfigPattern(name='listen_addresses', priority=Priority.HIGH,
          pattern=re.compile(r'listen_addresses\s*=\s*\'([^\']+)\'')),
      ConfigPattern(name='port', priority=Priority.LOW,
          pattern=re.compile(r'port\s*=\s*(\d+)')),
      ConfigPattern(name='password_encryption', priority=Priority.LOW,
          pattern=re.compile(r'password_encryption\s*=\s*(\S+)')),
      ConfigPattern(name='log_directory', priority=Priority.LOW,
          pattern=re.compile(r'log_directory\s*=\s*(\S+)')),
      ConfigPattern(name='log_timezone', priority=Priority.LOW,
          pattern=re.compile(r'log_timezone\s*=\s*\'([^\']+)\'')),
      ConfigPattern(name='cluster_name', priority=Priority.LOW,
          pattern=re.compile(r'cluster_name\s*=\s*\'([^\']+)\'')),
    ]

    for name, priority, pattern in config_pattern:
      name_re = re.compile(r'.*{0:s}\s+=.*'.format(name))
      for config_line in re.findall(name_re, data):
        if re.match(commented_line_re, config_line):
          err += f'Commented entry found {config_line}\n'
          continue

        try:
          config_value = re.match(pattern, config_line).group(1)

          # Access listening IP address
          # IP address can be comma separated list
          if name == 'listen_addresses':
            listen_addresses = []

            if ',' in config_value:
              listen_addresses = config_value.split(',')
            else:
              listen_addresses.append(config_value)

            if '*' in listen_addresses or '0.0.0.0' in listen_addresses:
              if module_priority > priority:
                module_summary = 'Listening on all interface IP addresses'
                module_priority = priority
              report.append(fmt.bullet(
                  'Listening on all interface IP addresses'))
            else:
              report.append(fmt.bullet(
                  'Listening on {0:s}'.format(', '.join(listen_addresses))))
          elif name == 'port':
            report.append(fmt.bullet(f'Listening on tcp port {config_value}'))
          elif name == 'password_encryption':
            report.append(fmt.bullet(
                f'Passwords encrypted with {config_value}'))
          elif name == 'log_timezone':
            report.append(fmt.bullet(f'Log time zone is {config_value}'))
        except AttributeError:
          err += f'Failed extracting value for {name}\n'
          continue

    module_report = '\n'.join(report)
    return (module_report, module_priority, module_summary), err

  def _analyze_pg_hba_config(self, config_data, result):
    """Analyze PostgreSQL client authentication config.

    Args:
      config_data (str): Content of pg_hba.conf file
      result (TurbiniaTaskResult): Used to log messages

    Returns:
      Tuple(
        module_report (str): Module report
        module_priority (int): The priority of module summary
        module_summary (str): A summary of the report (used for task status)
      )
    """
    ConfigPattern = namedtuple('ConfigPattern', ['name', 'priority', 'pattern'])
    config_patterns = [
      ConfigPattern(name='trust', priority=Priority.HIGH,
          pattern=re.compile(r'.*host.*trust')),
      ConfigPattern(name='md5_all', priority=Priority.MEDIUM,
          pattern=re.compile(r'.*host.*0.0.0.0.*md5')),
    ]

    module_priority = Priority.LOW
    module_summary = 'No weak client authentication configuration'
    module_report = ''

    report = []

    for _, _, pattern in config_patterns:
      for config_line in re.findall(pattern, config_data):
        # we don't want to process commented entries
        if re.match(r'^\s*#.*', config_line):
          continue

        hba = self._parse_hba_record(config_line)
        if not hba:
          result.log(f'Failed parsing config line {config_line}')
          continue

        if hba['connection_type'] == 'local':
          continue

        if '0.0.0.0' in hba['address'] and hba['method'] == 'trust':
          module_priority = Priority.CRITICAL
          module_summary = 'Unauthenticated access allowed from any IP address'
          report_line = ('Unauthentication access allowed from any IP address'
              ' to {0:s} database as database user {1:s}'.format(
              hba['database'], hba['user']))
          report.append(fmt.bullet(report_line))

        elif '0.0.0.0' not in hba['address'] and hba['method'] == 'trust':
          if module_priority > Priority.HIGH:
            module_priority = Priority.HIGH
            module_summary = 'Unauthenticated access alowed from {0:s}'.format(
                hba['address'])
          report_line = ('Unauthentication access allowed from {0:s} to {1:s}'
              ' database as database user {2:s}'.format(hba['address'],
              hba['database'], hba['user']))
          report.append(fmt.bullet(report_line))

        elif '0.0.0.0' in hba['address'] and hba['method'] == 'md5':
          if module_priority > Priority.MEDIUM:
            module_priority = Priority.MEDIUM
            module_summary = 'Authenticated access allowd from any IP address'
          report_line = ('Authenticated access allowed from any IP address to'
              ' {0:s} database as database user {1:s}'.format(
                hba['database'], hba['user']))
          report.append(fmt.bullet(report_line))

    module_report = '\n'.join(report)
    return (module_report, module_priority, module_summary)

  def _parse_hba_record(self, config_line):
    """ Parse pg_hba.conf configuration line.

    Args:
      config_line (str): Client authentication config line

    Returns:
      dict: Containing HBA record
    """
    config_line_re = re.compile(r'^\s*(\S+)\s*(\S+)\s*(\S+)\s*(\S+)\s*(\w+)')
    hba = {}

    match = config_line_re.match(config_line)
    if not match:
      return None

    hba['connection_type'] = match.group(1)
    hba['database'] = match.group(2)
    hba['user'] = match.group(3)

    if hba['connection_type'] == 'local':
      hba['address'] = 'N/A'
      hba['method'] = match.group(4)
    else:
      hba['address'] = match.group(4)
      hba['method'] = match.group(5)

    return hba

  def _analyze_linux_postgres_account(self, data):
    """Analyze linux postgres account.

    Args:
      data(str): Content of /etc/passwd file.

    Returns:
      Tuple(
        module_report (str): Module report
        module_priority (int): The priority of module summary
        module_summary (str): A summary of the report (used for task status)
      )
    """
    module_priority = Priority.LOW
    module_summary = 'No suspicious account configuration'
    module_report = ''

    report = []

    account, err = self._get_account_detail(data, _PG_ACCOUNT)
    if err:
      module_summary = 'Analysis failed'
      return (module_priority, module_summary, module_report)

    if account['gid'] == 0:
      module_priority = Priority.CRITICAL
      module_summary = 'postgres is member of root group'
      report_line = 'postgres is member of root group'
      report.append(fmt.bullet(report_line))

    if account['uid'] == 0:
      module_priority = Priority.CRITICAL
      module_summary = 'postgres is a root user'
      report_line = 'postgres is a root user with uid 0'
      report.append(fmt.bullet(report_line))

    if account['shell'] != '/bin/bash':
      if module_priority == Priority.LOW:
        module_summary = 'None default shell assiged to postgres'
      report_line = 'postgres shell is {0:s}. Default is /bin/bash'.format(
          account['shell'])
      report.append(fmt.bullet(report_line))

    module_report = '\n'.join(report)

    return (module_report, module_priority, module_summary)

  def _get_account_detail(self, passwd_data, user):
    """ Returns account detail dict for a user.

    Args:
      passwd_data (str): Content of /etc/passwd
      user (str): User account whose details needs to be extracted

    Returns:
      dict: containing user account information
      str: error message
    """
    user_re = re.compile(r'{0:s}:.*'.format(user))
    # dict holding parsed account information
    account = {}
    for passwd_line in re.findall(user_re, passwd_data):
      data = passwd_line.split(':')
      try:
        account['user'] = data[0]
        account['uid'] = int(data[2])
        account['gid'] = int(data[3])
        account['home'] = data[5]
        account['shell'] = data[6]
        break
      except KeyError:
        return None, f'Error parsing passwd entry {passwd_line}'
    return account, None

  def _analyze_shell_history(self, data):
    """Analyze *_history looking psql command.

    Args:
      data(str): Content of bash history

    Returns:
      Tuple(
        module_report (str): Module report
        module_priority (int): The priority of module summary
        module_summary (str): A summary of the report (used for task status)
      )
    """
    module_priority = Priority.LOW
    module_summary = 'No suspicious command found'
    module_report = ''

    report = []

    for name, priority, pattern in sqlcommands:
      for line in re.findall(pattern, data):
        module_priority = min(module_priority, priority)
        report.append(fmt.bullet(f'Suspicious {name} command: {line}'))

    if report:
      module_summary = '{0:d} suspicious commands found'.format(len(report))
    module_report = '\n'.join(report)

    return (module_report, module_priority, module_summary)

  def _collect_log_artifacts(self, evidence):
    """Extract postgresql log files.

    Args:
      evidence (Evidence): The evidence to process

    Returns:
      list(str): Path to extracted log files
    """
    artifact_definition_file = os.path.join(
        self.output_dir, 'postgresql_artifacts.yaml')

    with open(artifact_definition_file, 'wb') as fh:
      fh.write(_POSTGRESQL_ARTIFACTS.encode('utf8'))

    artifact_names = ['PostgreSQLLogFiles']
    try:
      collected_artifacts = extract_custom_artifacts(
          artifact_names=artifact_names,
          artifact_definition_file=artifact_definition_file,
          disk_path=evidence.local_path,
          output_dir=os.path.join(self.output_dir, 'artifacts'),
          credentials=evidence.credentials)
    except TurbiniaException as e:
      raise TurbiniaException(f'PostgreSQL log extraction failed: {e}') from e

    locations = []

    for collected_artifact in collected_artifacts:
      _, filename = os.path.split(collected_artifact)
      if re.match(r'postgresql-.*.log.*', filename):
        locations.append(collected_artifact)

    return locations

  def _analyze_postgresql_log(self, data):
    """Analyze postgresql log.

    Args:
      data(str): Content of log. Default is max 10 MB per file.

    Returns:
      Tuple(
        module_report (str): Module report
        module_priority (int): The priority of module summary
        module_summary (str): A summary of the report (used for task status)
      )
    """
    module_priority = Priority.LOW
    module_summary = 'No suspicious log entry'
    module_report = ''

    report = []

    LogPattern = namedtuple('LogPattern', ['name', 'priority', 'pattern'])
    log_patterns = [
      LogPattern(name='FROM PROGRAM execution',
          priority=Priority.CRITICAL,
          pattern=re.compile(r'.*\sFROM\s+PROGRAM\s+.*',
          re.IGNORECASE|re.MULTILINE)),
      LogPattern(name='Listening on all IPv4  interfaces',
          priority=Priority.MEDIUM,
          pattern=re.compile(r'.*listening on IPv4.*0.0.0.0.*')),
      LogPattern(name='Listening on all IPv6 interfaces',
          priority=Priority.MEDIUM,
          pattern=re.compile(r'.*listening on IPv6.*"::".*')),
      LogPattern(name='no_password_set', priority=Priority.MEDIUM,
          pattern=re.compile(r'.*User "\S+" has no password assigned')),
    ]

    # Linux commands to check in PostgreSQL logs
    linux_commands = ['sh', 'rm', 'curl', 'wget', 'find', 'cat', 'iptables',
                      'base64']
    for cmd in linux_commands:
      log_patterns.append(LogPattern(
          name=f'Linux command {cmd} execution',
          priority=Priority.MEDIUM,
          pattern=re.compile('{0:s}: .*'.format(cmd))))

    for name, event_priority, pattern in log_patterns:
      for line in re.findall(pattern, data):
        if module_priority > event_priority:
          module_priority = event_priority
          module_summary = f'{name} detected'
        report.append(fmt.bullet(line))

    module_report = '\n'.join(report)
    return (module_report, module_priority, module_summary)

  def _generate_report(self, reports):
    """Generate analysis report.

    Args:
      reports(list(namedtuple)): List of named tuple ModuleReport

    Returns:
      final_report(str): Overall report of the analysis
      final_summary(str): Overall summary of the analysis
    """
    report_heading = fmt.heading1('PostgreSQL Analysis')
    report_tldr = ''

    report = []
    summary = []
    final_priority = Priority.LOW

    for (module_name, artifact_path, module_priority, module_summary,
        module_report) in reports:
      summary.append((module_priority, fmt.bullet(module_summary)))

      report.append('{0:s}\n'.format(fmt.heading3(module_name)))
      report.append('{0:s}: {1:s}\n'.format(fmt.bold('Summary'),
                                            module_summary))
      report.append('{0:s}:'.format(fmt.bold('Details')))
      report.append(fmt.bullet(f'artifact path {artifact_path}'))
      report.append(module_report + '\n')

      final_priority = min(final_priority, module_priority)

    summary.sort(key=lambda x: int(x[0]))

    # Generate TLDR based on summay where summary priority is not LOW
    for summary_priority, summary_line in summary:
      if summary_priority == Priority.LOW:
        continue
      report_tldr += summary_line+'\n'

    # Create final report layout
    report.insert(0, report_heading)
    report.insert(1, '')
    report.insert(2, '{0:s}\n'.format(fmt.heading2('TLDR')))
    report.insert(3, '{0:s}\n'.format(report_tldr))
    report.insert(4, '{0:s}\n'.format(fmt.heading2('Detailed Analysis')))

    final_report = '\n'.join(report)
    final_summary = '\n'.join(x[1] for x in summary)

    return final_report, final_priority, final_summary

def read_file(filepath):
  """Reads the specified path and returns data"""
  with open(filepath, 'r') as fh:
    return fh.read()
