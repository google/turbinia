#!/usr/bin/env python
#
# Copyright 2017 Google Inc.
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
"""Command line interface for Turbinia."""

import argparse
import logging
import sys

from turbinia import config
from turbinia import TurbiniaException
from turbinia.debug import initialize_debugmode_if_requested
from turbinia.config import logger
from turbinia import __version__

# We set up the logger first without the file handler, and we will set up the
# file handler later once we have read the log path from the config.
logger.setup(need_file_handler=False)

log = logging.getLogger('turbinia')


def csv_list(string):
  """Helper method for having CSV argparse types.

  Args:
    string(str): Comma separated string to parse.

  Returns:
    list[str]: The parsed strings.
  """
  return string.split(',')


def check_args(source_path, args):
  """Checks lengths of supplied args match or raise an error.
     Lists can have only one element where they are automatically extended.

  Args:
    source_path(list(str)): List of source_paths supplied to turbiniactl.
    args(list(list)): List of args (i.e. name, source, partitions, etc) and
    their values supplied to turbiniactl.

  Raises:
    TurbiniaException: If length of args don't match.

  Returns:
    list(str): List of arg or None """
  ret = []
  if not args[0]:
    args[0] = source_path
  for arg in args:
    if not arg:
      arg = [None]
    if len(arg) > 1 and len(arg) != len(source_path):
      raise TurbiniaException(
          f'Number of passed in args {len(arg)} must equal to one or '
          f'number of source_paths/disks {len(source_path)}')
    if len(arg) == 1:
      arg = [arg[0] for _ in source_path]
    ret.append(arg)
  return ret


def process_args(args):
  """Parses and processes args.

  Args:
    args(namespace): turbiniactl args.

  Raises:
    TurbiniaException: If there's an error processing args.
  """
  parser = argparse.ArgumentParser(
      description=(
          'turbiniactl is used to start the different Turbinia '
          'components (e.g. API server, workers, Turbinia server).'))
  parser.add_argument(
      '-q', '--quiet', action='store_true', help='Show minimal output')
  parser.add_argument(
      '-d', '--debug', action='store_true', help='Show debug output',
      default=False)
  parser.add_argument(
      '-c', '--config_file', help='Load explicit config file. If specified it '
      'will ignore config files in other default locations '
      '(/etc/turbinia.conf, ~/.turbiniarc, or in paths referenced in '
      'environment variable TURBINIA_CONFIG_PATH)', required=False)
  parser.add_argument('-o', '--output_dir', help='Directory path for output')
  parser.add_argument('-L', '--log_file', help='Log file')
  parser.add_argument(
      '-V', '--version', action='version', version=__version__,
      help='Show the version')
  parser.add_argument(
      '-j', '--jobs_allowlist', default=[], type=csv_list,
      help='An allowlist for Jobs that will be allowed to run (in CSV format, '
      'no spaces). This will not force them to run if they are not configured '
      'to. This is applied both at server start time and when the client makes '
      'a processing request. When applied at server start time the change is '
      'persistent while the server is running.  When applied by the client, it '
      'will only affect that processing request.')
  parser.add_argument(
      '-J', '--jobs_denylist', default=[], type=csv_list,
      help='A denylist for Jobs we will not allow to run.  See '
      '--jobs_allowlist help for details on format and when it is applied.')

  subparsers = parser.add_subparsers(
      dest='command', title='Commands', metavar='<command>')
  # Action for printing config
  parser_config = subparsers.add_parser('config', help='Print out config file')
  parser_config.add_argument(
      '-f', '--file_only', action='store_true', help='Print out file path only')
  # Celery Worker
  subparsers.add_parser('celeryworker', help='Run Celery worker')
  # Server
  subparsers.add_parser('server', help='Run Turbinia Server')
  # API server
  subparsers.add_parser('api_server', help='Run Turbinia API server')

  args = parser.parse_args(args)

  # Load the config before final logger setup so we can the find the path to the
  # log file.
  try:
    if args.config_file:
      config.LoadConfig(config_file=args.config_file)
    else:
      config.LoadConfig()
  except TurbiniaException as exception:
    print(f'Could not load config file ({exception!s}).\n{config.CONFIG_MSG:s}')
    sys.exit(1)

  if args.log_file:
    user_specified_log = args.log_file

  config.TURBINIA_COMMAND = args.command
  flags_set = args.command in ('api_server', 'server', 'celeryworker')
  # Run logger setup again if we're running as a server or worker (or have a log
  # file explicitly set on the command line) to set a file-handler now that we
  # have the logfile path from the config.
  if flags_set or args.log_file:
    if args.log_file:
      logger.setup(log_file_path=user_specified_log)
    else:
      logger.setup()
  if args.quiet:
    log.setLevel(logging.ERROR)
  elif args.debug:
    log.setLevel(logging.DEBUG)
  else:
    log.setLevel(logging.INFO)

  log.info(f'Turbinia version: {__version__:s}')

  # Print out config if requested
  if args.command == 'config':
    if args.file_only:
      log.info(f'Config file path is {config.configSource:s}\n')
      sys.exit(0)
    try:
      with open(config.configSource, 'r', encoding='utf-8') as f:
        print(f.read())
        sys.exit(0)
    except IOError as exception:
      msg = (
          f'Failed to read config file {config.configSource:s}: {exception!s}')
      raise TurbiniaException(msg) from exception

  # Do late import of other needed Turbinia modules.  This is needed because the
  # config is loaded by these modules at load time, and we want to wait to load
  # the config until after we parse the args so that we can use those arguments
  # to point to config paths.
  elif args.command == 'celeryworker':
    initialize_debugmode_if_requested()
    # pylint: disable=import-outside-toplevel
    from turbinia.worker import TurbiniaCeleryWorker
    worker = TurbiniaCeleryWorker(
        jobs_denylist=args.jobs_denylist, jobs_allowlist=args.jobs_allowlist)
    worker.start()
  elif args.command == 'server':
    initialize_debugmode_if_requested()
    # pylint: disable=import-outside-toplevel
    from turbinia.server import TurbiniaServer
    server = TurbiniaServer(
        jobs_denylist=args.jobs_denylist, jobs_allowlist=args.jobs_allowlist)
    server.start()
  elif args.command == 'api_server':
    initialize_debugmode_if_requested()
    # pylint: disable=import-outside-toplevel
    from turbinia.api.api_server import TurbiniaAPIServer
    api_server = TurbiniaAPIServer()
    api_server.start('turbinia.api.api_server:app')


def main():
  """Main function for turbiniactl"""
  try:
    process_args(sys.argv[1:])
  except TurbiniaException as exception:
    log.error(f'{str(exception):s}')
  log.info('Done.')
  sys.exit(0)


if __name__ == '__main__':
  main()
