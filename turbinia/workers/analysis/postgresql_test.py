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
"""Tests for the PostgreSQL analysis task."""

import os
import unittest

from turbinia import config
from turbinia.workers.analysis import postgresql
from turbinia.workers import TurbiniaTaskResult
from turbinia.workers import Priority
from turbinia.workers.workers_test import TestTurbiniaTaskBase


class PostgreSQLAnalysisTaskTest(TestTurbiniaTaskBase):
  """Tests for PostgreSQLAnalysisTask."""

  TEST_DATA_DIR = None

  # Evidence mount point location i.e. Evidence.local_path
  # Use export EVIDENCE_LOCAL_PATH='/mnt/mock' where test image is mounted
  # to /mnt/mock
  EVIDENCE_LOCAL_PATH = os.environ.get('EVIDENCE_LOCAL_PATH')
  OUTPUT_DIR = '/tmp/postgresql-output'

  # pylint: disable=line-too-long
  POSTGRESQL_CONF = """data_directory = '/var/lib/postgresql/13/main'          # use data in another directory
hba_file = '/etc/postgresql/13/main/pg_hba.conf'        # host-based authentication file
ident_file = '/etc/postgresql/13/main/pg_ident.conf'    # ident configuration file
listen_addresses = 'localhost,10.128.0.11'              # what IP address(es) to listen on;
port = 5432                             # (change requires restart)
#password_encryption = md5              # md5 or scram-sha-256
log_timezone = 'Etc/UTC'
cluster_name = '13/main'                        # added to process titles if nonempty
  """

  POSTGRESQL_CONF_OUTPUT = {
      'summary': 'Listening on a routable interface',
      'priority': Priority.LOW,
      'report': """* PostgreSQL listening on localhost,10.128.0.11
* Listening on port 5432
* Password is encrypted with md5
* Log timezone is Etc/UTC""",
  }

  # pylint: disable=line-too-long
  PG_HBA_CONF = """local   all             postgres                                peer
local   all             all                                     peer
host    all             all             127.0.0.1/32            md5
host      all             all             0.0.0.0/0               md5
hostssl all             all             0.0.0.0/0               trust
host    all             john            100.100.100.100         trust
host    all             john            100.100.100.101         md5
host    all             all             ::1/128                 md5
local   replication     all                                     peer
host    replication     all             127.0.0.1/32            md5
host    replication     all             ::1/128                 md5
"""

  # pylint: disable=line-too-long
  PG_HBA_OUTPUT = {
      'summary': 'Unauthenticated access allowed from any IP address',
      'priority': Priority.CRITICAL,
      'report': """* Unauthentication access allowed from any IP address to all database as database user all
* Unauthentication access allowed from 100.100.100.100 to all database as database user john
* Authenticated access allowed from any IP address to all database as database user all""",
  }

  # pylint: disable=line-too-long
  PASSWD = 'postgres:x:0:114:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash'
  ACCOUNT_OUTPUT = {
      'user': 'postgres',
      'uid': 0,
      'gid': 114,
      'home': '/var/lib/postgresql',
      'shell': '/bin/bash',
  }

  # Bash History
  BASH_HISTORY = """psql
exit
pg_restore -U postgres -d dvdrental /tmp/dvdrental.tar 
psql
ls
exit
psql -U john -d dvdrental
psql -U john -d dvdrental -p 
psql -U john -d dvdrental -p 
psql -U postgres -d dvdrental
exit
psql
exit"""

  BASH_HISTORY_OUTPUT = {
      'summary': 'No suspicious command found',
      'priority': Priority.LOW,
      'report': '',
  }

  # Psql History
  PSQL_HISTORY = """create database dvdrental;
select * from actor;
select count(id) category;
select * from film limit 10;
select count(film_id) from film;
create user john with password 'skfjsaljflkdsajflkdsjflkdsajflkdsjfds';
grant all privileges on database dvdrental to john;
alter user john with password 'johndoe';
grant all privileges on database dvdrental to john;
"""

  PSQL_HISTORY_OUTPUT = {
      'summary': '3 suspicious commands found',
      'priority': Priority.LOW,
      'report': """* Suspicious select_all command: select * from actor;
* Suspicious select_all command: select * from film limit 10;
* Suspicious select_count command: select count(film_id) from film;""",
  }

  # Postgresql Log
  # pylint: disable=line-too-long
  POSTGRESQL_LOG = '''2022-02-23 15:21:45.047 UTC [29717] [unknown]@[unknown] LOG:  invalid length of startup packet
2022-02-23 15:21:49.153 UTC [29753] [unknown]@[unknown] LOG:  invalid length of startup packet
2022-02-23 15:21:52.550 UTC [29778] [unknown]@[unknown] LOG:  invalid length of startup packet
2022-07-11 05:49:52.855 UTC [59566] LOG:  listening on IPv4 address "0.0.0.0", port 5432
2022-07-11 05:49:52.855 UTC [59566] LOG:  listening on IPv6 address "::", port 5432
2022-07-11 05:49:52.858 UTC [59566] LOG:  listening on Unix socket "/var/run/postgresql/.s.PGSQL.5432
cat: /root/.bash_history: Permission denied
cat: '~/*/.ssh/known_hosts': No such file or directory
sh: 142: cannot create /var/log/wtmp: Permission denied
sh: 144: cannot create /var/log/cron: Permission denied
'''

  # pylint: disable=line-too-long
  POSTGRESQL_LOG_OUTPUT = {
      'summary': 'Listening on all IPv4  interfaces detected',
      'priority': Priority.MEDIUM,
      'report': '''* 2022-07-11 05:49:52.855 UTC [59566] LOG:  listening on IPv4 address "0.0.0.0", port 5432
* 2022-07-11 05:49:52.855 UTC [59566] LOG:  listening on IPv6 address "::", port 5432
* sh: 142: cannot create /var/log/wtmp: Permission denied
* sh: 144: cannot create /var/log/cron: Permission denied
* cat: /root/.bash_history: Permission denied
* cat: '~/*/.ssh/known_hosts': No such file or directory''',
  }

  def setUp(self):
    super(PostgreSQLAnalysisTaskTest, self).setUp()
    self.setResults(mock_run=False)
    filedir = os.path.dirname(os.path.realpath(__file__))
    self.TEST_DATA_DIR = os.path.join(filedir, '..', '..', '..', 'test_data')
    self.evidence.local_path = self.TEST_DATA_DIR

  def test_analyze_postgresql_config(self):
    """Test the _analyze_postgresql_config method."""
    config.LoadConfig()
    task = postgresql.PostgreSQLAnalysisTask()

    # pylint: disable=protected-access
    pg_config = task._read_postgresql_config(self.POSTGRESQL_CONF)
    # pylint: disable=protected-access
    (report, priority, summary) = task._analyze_postgresql_config(pg_config)

    module_output = {
        'summary': summary,
        'priority': priority,
        'report': report,
    }

    self.assertEqual(module_output, self.POSTGRESQL_CONF_OUTPUT)

  def test_analyze_pg_hba_config(self):
    """Test the _analyze_pg_hba_config method."""
    config.LoadConfig()
    task = postgresql.PostgreSQLAnalysisTask()
    result = TurbiniaTaskResult()

    # pylint: disable=protected-access
    (report, priority, summary) = task._analyze_pg_hba_config(
        self.PG_HBA_CONF, result)
    module_output = {
        'summary': summary,
        'priority': priority,
        'report': report,
    }

    self.assertEqual(module_output, self.PG_HBA_OUTPUT)

  def test_get_account_detail(self):
    """Test the _get_account_detail method."""
    config.LoadConfig()
    task = postgresql.PostgreSQLAnalysisTask()

    # pylint: disable=protected-access
    account, _ = task._get_account_detail(self.PASSWD, 'postgres')
    self.assertEqual(account, self.ACCOUNT_OUTPUT)

  def test_analyze_bash_history(self):
    """Test the _analyze_bash_history method."""
    config.LoadConfig()
    task = postgresql.PostgreSQLAnalysisTask()

    # pylint: disable=protected-access
    (report, priority, summary) = task._analyze_shell_history(self.BASH_HISTORY)
    module_output = {
        'summary': summary,
        'priority': priority,
        'report': report,
    }

    self.assertEqual(module_output, self.BASH_HISTORY_OUTPUT)

  def test_analyze_psql_history(self):
    """Test the _analyze_psql_history method."""
    config.LoadConfig()
    task = postgresql.PostgreSQLAnalysisTask()

    # pylint: disable=protected-access
    (report, priority, summary) = task._analyze_shell_history(self.PSQL_HISTORY)
    module_output = {
        'summary': summary,
        'priority': priority,
        'report': report,
    }

    self.assertEqual(module_output, self.PSQL_HISTORY_OUTPUT)

  def test_analyze_postgresql_log(self):
    """Test the _analyze_postgresql_log method."""
    config.LoadConfig()
    task = postgresql.PostgreSQLAnalysisTask()

    # pylint: disable=protected-access
    (report, priority, summary) = task._analyze_postgresql_log(
        self.POSTGRESQL_LOG)
    module_output = {
        'summary': summary,
        'priority': priority,
        'report': report,
    }

    self.assertEqual(module_output, self.POSTGRESQL_LOG_OUTPUT)

if __name__ == '__main__':
  unittest.main()
