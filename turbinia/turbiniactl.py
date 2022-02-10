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
# pylint: disable=bad-indentation

from __future__ import print_function
from __future__ import unicode_literals

import argparse
import getpass
import logging
import os
import sys
import uuid

from turbinia import config
from turbinia import TurbiniaException
from turbinia.lib import recipe_helpers
from turbinia.config import logger
from turbinia import __version__
from turbinia.processors import archive
from turbinia.output_manager import OutputManager
from turbinia.output_manager import GCSOutputWriter

log = logging.getLogger('turbinia')
# We set up the logger first without the file handler, and we will set up the
# file handler later once we have read the log path from the config.
logger.setup(need_file_handler=False)


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
  ret = list()
  if not args[0]:
    args[0] = source_path
  for arg in args:
    if not arg:
      arg = [None]
    if len(arg) > 1 and len(arg) != len(source_path):
      raise TurbiniaException(
          'Number of passed in args ({0:d}) must equal to one or '
          'number of source_paths/disks ({1:d}).'.format(
              len(arg), len(source_path)))
    if len(arg) == 1:
      arg = [arg[0] for _ in source_path]
    ret.append(arg)
  return ret


def process_args(args):
  """Parses and processes args.
  
  Args:
    args(namespace): turbiniactl args.
  
  Raises:
    TurbiniaException: If theres an error processing args.
  """
  parser = argparse.ArgumentParser(
      description='Turbinia can bulk process multiple evidence of same type '
      '(i.e. rawdisk, google cloud disk). For bulk processing, pass in csv '
      'list of args to be processed. If all pieces of evidence share the same '
      'property, such as project or source, there is no need for repeating '
      'those values in the command.')
  parser.add_argument(
      '-q', '--quiet', action='store_true', help='Show minimal output')
  parser.add_argument(
      '-v', '--verbose', action='store_true', help='Show verbose output',
      default=True)
  parser.add_argument(
      '-d', '--debug', action='store_true', help='Show debug output',
      default=False)
  parser.add_argument(
      '-a', '--all_fields', action='store_true',
      help='Show all task status fields in output', required=False)
  parser.add_argument(
      '-c', '--config_file', help='Load explicit config file. If specified it '
      'will ignore config files in other default locations '
      '(/etc/turbinia.conf, ~/.turbiniarc, or in paths referenced in '
      'environment variable TURBINIA_CONFIG_PATH)', required=False)
  parser.add_argument(
      '-I', '--recipe', help='Name of Recipe to be employed on evidence',
      required=False)
  parser.add_argument(
      '-P', '--recipe_path', help='Recipe file path to load and use.',
      required=False)
  parser.add_argument(
      '-X', '--skip_recipe_validation', action='store_true', help='Do not '
      'perform recipe validation on the client.', required=False, default=False)
  parser.add_argument(
      '-f', '--force_evidence', action='store_true',
      help='Force evidence processing request in potentially unsafe conditions',
      required=False)
  parser.add_argument(
      '-k', '--decryption_keys', help='Decryption keys to be passed in as '
      ' comma separated list. Each entry should be in the form type=key. (e.g. '
      '"-k password=123456,recovery_password=XXXX-XXXX-XXXX-XXXX-XXXX-XXXX")',
      default=[], type=csv_list)
  parser.add_argument('-o', '--output_dir', help='Directory path for output')
  parser.add_argument('-L', '--log_file', help='Log file')
  parser.add_argument(
      '-r', '--request_id', help='Create new requests with this Request ID',
      required=False)
  parser.add_argument(
      '-V', '--version', action='version', version=__version__,
      help='Show the version')
  parser.add_argument(
      '-D', '--dump_json', action='store_true',
      help='Dump JSON output of Turbinia Request instead of sending it')
  parser.add_argument(
      '-F', '--filter_patterns_file',
      help='A file containing newline separated string patterns to filter '
      'text based evidence files with (in extended grep regex format). '
      'This filtered output will be in addition to the complete output')
  parser.add_argument(
      '-Y', '--yara_rules_file', help='A file containing Yara rules.')
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
  parser.add_argument(
      '-p', '--poll_interval', default=60, type=int,
      help='Number of seconds to wait between polling for task state info')

  parser.add_argument(
      '-T', '--debug_tasks', action='store_true',
      help='Show debug output for all supported tasks', default=False)
  parser.add_argument(
      '-w', '--wait', action='store_true',
      help='Wait to exit until all tasks for the given request have completed')
  subparsers = parser.add_subparsers(
      dest='command', title='Commands', metavar='<command>')

  # Action for printing config
  parser_config = subparsers.add_parser('config', help='Print out config file')
  parser_config.add_argument(
      '-f', '--file_only', action='store_true', help='Print out file path only')

  #Sends Test Notification
  parser_testnotify = subparsers.add_parser(
      'testnotify', help='Sends test notification')

  # TODO(aarontp): Find better way to specify these that allows for multiple
  # pieces of evidence to be submitted. Maybe automagically create different
  # commands based on introspection of evidence objects?
  # RawDisk
  parser_rawdisk = subparsers.add_parser(
      'rawdisk', help='Process RawDisk as Evidence (bulk processable)')
  parser_rawdisk.add_argument(
      '-l', '--source_path', help='Local path to the evidence', required=True,
      type=csv_list)
  parser_rawdisk.add_argument(
      '-s', '--source', help='Description of the source of the evidence',
      required=False, type=csv_list, default=[None])
  parser_rawdisk.add_argument(
      '-n', '--name', help='Descriptive name of the evidence', required=False,
      type=csv_list)

  # Parser options for Google Cloud Disk Evidence type
  parser_googleclouddisk = subparsers.add_parser(
      'googleclouddisk',
      help='Process Google Cloud Persistent Disk as Evidence '
      '(bulk processable)')
  parser_googleclouddisk.add_argument(
      '-C', '--copy_only', action='store_true', help='Only copy disk and do '
      'not process with Turbinia. This only takes effect when a source '
      '--project is defined and can be run without any Turbinia server or '
      'workers configured.')
  parser_googleclouddisk.add_argument(
      '-d', '--disk_name', help='Google Cloud name for disk', required=True,
      type=csv_list)
  parser_googleclouddisk.add_argument(
      '-p', '--project', help='Project that the disk to process is associated '
      'with. If this is different from the project that Turbinia is running '
      'in, it will be copied to the Turbinia project.', type=csv_list)
  parser_googleclouddisk.add_argument(
      '-z', '--zone', help='Geographic zone the disk exists in', type=csv_list)
  parser_googleclouddisk.add_argument(
      '-s', '--source', help='Description of the source of the evidence',
      required=False, type=csv_list, default=[None])
  parser_googleclouddisk.add_argument(
      '-n', '--name', help='Descriptive name of the evidence', required=False,
      type=csv_list)

  # Parser options for Google Cloud Persistent Disk Embedded Raw Image
  parser_googleclouddiskembedded = subparsers.add_parser(
      'googleclouddiskembedded',
      help='Process Google Cloud Persistent Disk with an embedded raw disk '
      'image as Evidence (bulk processable)')
  parser_googleclouddiskembedded.add_argument(
      '-C', '--copy_only', action='store_true', help='Only copy disk and do '
      'not process with Turbinia. This only takes effect when a source '
      '--project is defined and can be run without any Turbinia server or '
      'workers configured.')
  parser_googleclouddiskembedded.add_argument(
      '-e', '--embedded_path',
      help='Path within the Persistent Disk that points to the raw image file',
      required=True, type=csv_list)
  parser_googleclouddiskembedded.add_argument(
      '-d', '--disk_name', help='Google Cloud name for disk', required=True,
      type=csv_list)
  parser_googleclouddiskembedded.add_argument(
      '-p', '--project', help='Project that the disk to process is associated '
      'with. If this is different from the project that Turbinia is running '
      'in, it will be copied to the Turbinia project.', type=csv_list)

  parser_googleclouddiskembedded.add_argument(
      '-P', '--mount_partition', type=csv_list, default=[1],
      help='The partition number as an integer to use when mounting the '
      'parent disk. Defaults to the first partition. Only affects mounting, and '
      'not what gets processed.')
  parser_googleclouddiskembedded.add_argument(
      '-z', '--zone', help='Geographic zone the disk exists in', type=csv_list)
  parser_googleclouddiskembedded.add_argument(
      '-s', '--source', help='Description of the source of the evidence',
      required=False, type=csv_list, default=[None])
  parser_googleclouddiskembedded.add_argument(
      '-n', '--name', help='Descriptive name of the evidence', required=False,
      type=csv_list)

  # RawMemory
  parser_rawmemory = subparsers.add_parser(
      'rawmemory', help='Process RawMemory as Evidence (bulk processable)')
  parser_rawmemory.add_argument(
      '-l', '--source_path', help='Local path to the evidence', required=True,
      type=csv_list)
  parser_rawmemory.add_argument(
      '-P', '--profile', help='Profile to use with Volatility', required=True,
      type=csv_list)
  parser_rawmemory.add_argument(
      '-n', '--name', help='Descriptive name of the evidence', required=False,
      type=csv_list)
  parser_rawmemory.add_argument(
      '-m', '--module_list', type=csv_list,
      help='Volatility module(s) to execute', required=True)

  # Parser options for Directory evidence type
  parser_directory = subparsers.add_parser(
      'directory', help='Process a directory as Evidence (bulk processable)')
  parser_directory.add_argument(
      '-l', '--source_path', help='Local path to the evidence', required=True,
      type=csv_list)
  parser_directory.add_argument(
      '-s', '--source', help='Description of the source of the evidence',
      required=False, type=csv_list, default=[None])
  parser_directory.add_argument(
      '-n', '--name', help='Descriptive name of the evidence', required=False,
      type=csv_list)

  # Parser options for CompressedDirectory evidence type
  parser_directory = subparsers.add_parser(
      'compresseddirectory', help='Process a compressed tar file as Evidence '
      '(bulk processable)')
  parser_directory.add_argument(
      '-l', '--source_path', help='Local path to the evidence', required=True,
      type=csv_list)
  parser_directory.add_argument(
      '-s', '--source', help='Description of the source of the evidence',
      required=False, type=csv_list, default=[None])
  parser_directory.add_argument(
      '-n', '--name', help='Descriptive name of the evidence', required=False,
      type=csv_list)

  # Parser options for ChromiumProfile evidence type
  parser_hindsight = subparsers.add_parser(
      'hindsight', help='Process ChromiumProfile as Evidence '
      '(bulk processable)')
  parser_hindsight.add_argument(
      '-l', '--source_path', help='Local path to the evidence', required=True,
      type=csv_list)
  parser_hindsight.add_argument(
      '-f', '--format', help='Output format (supported types are '
      'xlsx, sqlite, jsonl)', type=csv_list, default=['sqlite'])
  parser_hindsight.add_argument(
      '-b', '--browser_type', help='The type of browser the input files belong'
      'to (supported types are Chrome, Brave)', type=csv_list,
      default=['Chrome'])
  parser_hindsight.add_argument(
      '-n', '--name', help='Descriptive name of the evidence', required=False,
      type=csv_list)

  # List Jobs
  subparsers.add_parser(
      'listjobs',
      help='List all available Jobs. These Job names can be used by '
      '--jobs_allowlist and --jobs_denylist')

  # PSQ Worker
  parser_psqworker = subparsers.add_parser('psqworker', help='Run PSQ worker')
  parser_psqworker.add_argument(
      '-S', '--single_threaded', action='store_true',
      help='Run PSQ Worker in a single thread', required=False)

  # Celery Worker
  subparsers.add_parser('celeryworker', help='Run Celery worker')

  # Parser options for Turbinia status command
  parser_status = subparsers.add_parser(
      'status', help='Get Turbinia Task status')
  parser_status.add_argument(
      '-c', '--close_tasks', action='store_true',
      help='Close tasks based on Request ID or Task ID', required=False)
  parser_status.add_argument(
      '-C', '--csv', action='store_true',
      help='When used with --statistics, the output will be in CSV format',
      required=False)
  parser_status.add_argument(
      '-d', '--days_history', default=0, type=int,
      help='Number of days of history to show', required=False)
  parser_status.add_argument(
      '-D', '--dump_json', action='store_true',
      help='Dump JSON status output instead text. Compatible with -d, -u, '
      '-r and -t flags, but not others')
  parser_status.add_argument(
      '-f', '--force', help='Gatekeeper for --close_tasks', action='store_true',
      required=False)
  parser_status.add_argument(
      '-r', '--request_id',
      help='Show all tasks for this Request ID. A request to process Evidence will '
      'generate a unique request ID and this option will show all Tasks associated '
      'with this request.', required=False)
  # 20 == Priority.High. We are setting this manually here because we don't want
  # to load the worker module yet in order to access this Enum.
  parser_status.add_argument(
      '-p', '--priority_filter', default=20, type=int, required=False,
      help='This sets what report sections are shown in full detail in '
      'report output.  Any tasks that have set a report_priority value '
      'equal to or lower than this setting will be shown in full detail, and '
      'tasks with a higher value will only have a summary shown.  To see all '
      'tasks report output in full detail, set --priority_filter=100')
  parser_status.add_argument(
      '-R', '--full_report',
      help='Generate full markdown report instead of just a summary',
      action='store_true', required=False)
  parser_status.add_argument(
      '-s', '--statistics', help='Generate statistics only',
      action='store_true', required=False)
  parser_status.add_argument(
      '-t', '--task_id', help='Show task data for the given Task ID. A '
      'processing request can generate multiple Tasks as part of the request '
      'and this will filter to only the specified Task.', required=False)
  parser_status.add_argument(
      '-u', '--user', help='Show task for given user', required=False)
  parser_status.add_argument(
      '-i', '--requests', required=False, action='store_true',
      help='Show all requests from a specified timeframe. The default '
      'timeframe is 7 days. Please use the -d flag to extend this.')
  parser_status.add_argument(
      '-g', '--group_id', help='Show Requests for given group ID. This command'
      ' only shows the related requests and overview of their task status. Run '
      '--full_report for the full list of requests and their tasks.',
      required=False)
  parser_status.add_argument(
      '-w', '--workers', required=False, action='store_true',
      help='Show Worker status information from a specified timeframe. The '
      'default timeframe is 7 days. Please use the -d flag to extend this. '
      'Additionaly, you can use the -a or --all_fields flag to retrieve the '
      'full output containing finished and unassigned worker tasks.')
  parser_log_collector = subparsers.add_parser(
      'gcplogs', help='Collects Turbinia logs from Stackdriver.')
  parser_log_collector.add_argument(
      '-o', '--output_dir', help='Directory path for output', required=False)
  parser_log_collector.add_argument(
      '-q', '--query',
      help='Filter expression to use to query Stackdriver logs.')
  parser_log_collector.add_argument(
      '-d', '--days_history', default=1, type=int,
      help='Number of days of history to show', required=False)
  parser_log_collector.add_argument(
      '-s', '--server_logs', action='store_true',
      help='Collects all server related logs.')
  parser_log_collector.add_argument(
      '-w', '--worker_logs', action='store_true',
      help='Collects all worker related logs.')

  # Add GCS logs collector
  parser_gcs_logs = subparsers.add_parser(
      'dumpgcs', help='Get Turbinia results from Google Cloud Storage.')
  parser_gcs_logs.add_argument(
      '-o', '--output_dir', help='Directory path for output.', required=True)
  parser_gcs_logs.add_argument(
      '-t', '--task_id', help='Download all the results for given task_id.')
  parser_gcs_logs.add_argument(
      '-r', '--request_id',
      help='Download the results for all Tasks for the given request_id.')
  parser_gcs_logs.add_argument(
      '-b', '--bucket',
      help='Alternate GCS bucket to download from. Must be in the following '
      'format gs://{BUCKET_NAME}/. Defaults to the BUCKET_NAME as specified '
      'in the config')
  parser_gcs_logs.add_argument(
      '-d', '--days_history', default=0, type=int,
      help='Number of days of history to to query results for', required=False)
  parser_gcs_logs.add_argument(
      '-i', '--instance_id',
      help='Instance ID used to run tasks/requests. You must provide an '
      'instance ID if the task/request was not processed on the same instance '
      'as your confing file.')
  # Server
  subparsers.add_parser('server', help='Run Turbinia Server')

  args = parser.parse_args(args)

  # Load the config before final logger setup so we can the find the path to the
  # log file.
  try:
    if args.config_file:
      config.LoadConfig(config_file=args.config_file)
    else:
      config.LoadConfig()
  except TurbiniaException as exception:
    print(
        'Could not load config file ({0!s}).\n{1:s}'.format(
            exception, config.CONFIG_MSG))
    sys.exit(1)

  if args.log_file:
    user_specified_log = args.log_file
  if args.output_dir:
    config.OUTPUT_DIR = args.output_dir

  config.TURBINIA_COMMAND = args.command
  server_flags_set = args.command == 'server'
  worker_flags_set = args.command in ('psqworker', 'celeryworker')
  # Run logger setup again if we're running as a server or worker (or have a log
  # file explicitly set on the command line) to set a file-handler now that we
  # have the logfile path from the config.
  if server_flags_set or worker_flags_set or args.log_file:
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

  # Enable tasks debugging for supported tasks
  if args.debug_tasks:
    config.DEBUG_TASKS = True

  if config.TASK_MANAGER == 'PSQ':
    from turbinia.lib import google_cloud
    from libcloudforensics.providers.gcp import forensics as gcp_forensics

  # Enable GCP Stackdriver Logging
  if config.STACKDRIVER_LOGGING and args.command in ('server', 'psqworker'):
    google_cloud.setup_stackdriver_handler(
        config.TURBINIA_PROJECT, args.command)

  log.info('Turbinia version: {0:s}'.format(__version__))

  # Do late import of other needed Turbinia modules.  This is needed because the
  # config is loaded by these modules at load time, and we want to wait to load
  # the config until after we parse the args so that we can use those arguments
  # to point to config paths.
  from turbinia import notify
  from turbinia import client as TurbiniaClientProvider
  from turbinia.worker import TurbiniaCeleryWorker
  from turbinia.worker import TurbiniaPsqWorker
  from turbinia.server import TurbiniaServer

  # Print out config if requested
  if args.command == 'config':
    if args.file_only:
      log.info('Config file path is {0:s}\n'.format(config.configSource))
      sys.exit(0)

    try:
      with open(config.configSource, "r") as f:
        print(f.read())
        sys.exit(0)
    except IOError as exception:
      msg = (
          'Failed to read config file {0:s}: {1!s}'.format(
              config.configSource, exception))
      raise TurbiniaException(msg)
  #sends test notification
  if args.command == 'testnotify':
    notify.sendmail(
        config.EMAIL_ADDRESS, 'Turbinia test notification',
        'This is a test notification')
    sys.exit(0)

  args.jobs_allowlist = [j.lower() for j in args.jobs_allowlist]
  args.jobs_denylist = [j.lower() for j in args.jobs_denylist]

  # Read set set filter_patterns
  filter_patterns = []
  if (args.filter_patterns_file and
      not os.path.exists(args.filter_patterns_file)):
    msg = 'Filter patterns file {0:s} does not exist.'.format(
        args.filter_patterns_file)
    raise TurbiniaException(msg)
  elif args.filter_patterns_file:
    try:
      filter_patterns = open(args.filter_patterns_file).read().splitlines()
    except IOError as e:
      log.warning(
          'Cannot open file {0:s} [{1!s}]'.format(args.filter_patterns_file, e))

  # Read yara rules
  yara_rules = ''
  if (args.yara_rules_file and not os.path.exists(args.yara_rules_file)):
    msg = 'Filter patterns file {0:s} does not exist.'.format(
        args.yara_rules_file)
    raise TurbiniaException(msg)
  elif args.yara_rules_file:
    try:
      yara_rules = open(args.yara_rules_file).read()
    except IOError as e:
      msg = ('Cannot open file {0:s} [{1!s}]'.format(args.yara_rules_file, e))
      raise TurbiniaException(msg)

  # Create Client object
  client = None
  if args.command not in ('psqworker', 'server'):
    client = TurbiniaClientProvider.get_turbinia_client()

  # Set group id
  group_id = uuid.uuid4().hex

  # Checks for bulk processing
  if args.command in ('rawdisk', 'directory', 'compresseddirectory'):
    args.name, args.source = check_args(
        args.source_path, [args.name, args.source])
    # Iterate through evidence and call process_evidence
    for i, source_path in enumerate(args.source_path):
      name = args.name[i]
      source = args.source[i]
      process_evidence(
          args=args, source_path=source_path, name=name, source=source,
          group_id=group_id, filter_patterns=filter_patterns, client=client,
          yara_rules=yara_rules)
  elif args.command in ('googleclouddisk', 'googleclouddiskembedded'):
    # Fail if this is a local instance
    if config.SHARED_FILESYSTEM and not args.force_evidence:
      msg = (
          'The evidence type {0:s} is Cloud only, and this instance of '
          'Turbinia is not a cloud instance.'.format(args.command))
      raise TurbiniaException(msg)
    # Check cloud zones
    if not args.zone and config.TURBINIA_ZONE:
      args.zone = [config.TURBINIA_ZONE]
    elif not args.zone and not config.TURBINIA_ZONE:
      msg = 'Turbinia zone must be set by --zone or in config.'
      raise TurbiniaException(msg)
    # Checks for cloud project
    if not args.project and config.TURBINIA_PROJECT:
      args.project = [config.TURBINIA_PROJECT]
    elif not args.project and not config.TURBINIA_PROJECT:
      msg = 'Turbinia project must be set by --project or in config'
      raise TurbiniaException(msg)
    # Since mount_partition and embedded_path are not in cloud disk namespace,
    # Setting them to None here
    if args.command == 'googleclouddisk':
      args.mount_partition = None
      args.embedded_path = None
    (
        args.name, args.source, args.project, args.zone, args.mount_partition,
        args.embedded_path) = check_args(
            args.disk_name, [
                args.name, args.source, args.project, args.zone,
                args.mount_partition, args.embedded_path
            ])
    mount_partition = None
    embedded_path = None
    for i, disk_name in enumerate(args.disk_name):
      project = args.project[i]
      zone = args.zone[i]
      name = args.name[i]
      source = args.source[i]
      if args.command == 'googleclouddiskembedded':
        embedded_path = args.embedded_path[i]
        mount_partition = args.mount_partition[i]
      if ((project and project != config.TURBINIA_PROJECT) or
          (zone and zone != config.TURBINIA_ZONE)):
        new_disk = gcp_forensics.CreateDiskCopy(
            project, config.TURBINIA_PROJECT, None, config.TURBINIA_ZONE,
            disk_name=disk_name)
        disk_name = new_disk.name
        if args.copy_only:
          log.info(
              '--copy_only specified, so not processing {0:s} with '
              'Turbinia'.format(disk_name))
          continue

      process_evidence(
          args=args, disk_name=disk_name, name=name, source=source,
          project=project, zone=zone, embedded_path=embedded_path,
          mount_partition=mount_partition, group_id=group_id,
          filter_patterns=filter_patterns, client=client, yara_rules=yara_rules)
  elif args.command == 'rawmemory':
    # Checks if length of args match
    args.name, args.profile = check_args(
        args.source_path, [args.name, args.profile])
    for i, source_path in enumerate(args.source_path):
      profile = args.profile[i]
      name = args.name[i]
      process_evidence(
          args=args, source_path=source_path, name=name, profile=profile,
          group_id=group_id, filter_patterns=filter_patterns, client=client,
          yara_rules=yara_rules)
  elif args.command == 'hindsight':
    args.name, args.browser_type, args.format = check_args(
        args.source_path, [args.name, args.browser_type, args.format])
    for i, source_path in enumerate(args.source_path):
      name = args.name[i]
      browser_type = args.browser_type[i]
      format = args.format[i]
      process_evidence(
          args=args, source_path=source_path, name=name, format=format,
          group_id=group_id, client=client, filter_patterns=filter_patterns,
          yara_rules=yara_rules, browser_type=browser_type)
  elif args.command == 'psqworker':
    # Set up root logger level which is normally set by the psqworker command
    # which we are bypassing.
    logger.setup()
    worker = TurbiniaPsqWorker(
        jobs_denylist=args.jobs_denylist, jobs_allowlist=args.jobs_allowlist)
    worker.start()
  elif args.command == 'celeryworker':
    logger.setup()
    worker = TurbiniaCeleryWorker(
        jobs_denylist=args.jobs_denylist, jobs_allowlist=args.jobs_allowlist)
    worker.start()
  elif args.command == 'server':
    server = TurbiniaServer(
        jobs_denylist=args.jobs_denylist, jobs_allowlist=args.jobs_allowlist)
    server.start()
  elif args.command == 'status':
    region = config.TURBINIA_REGION
    if args.request_id and args.group_id:
      msg = (
          'Cannot run status command with request ID and group ID. Please '
          'only specify one.')
      raise TurbiniaException(msg)
    if args.close_tasks:
      if args.group_id:
        msg = 'The --close_task flag is not compatible with --group_id.'
        raise TurbiniaException(msg)
      if args.user or args.request_id or args.task_id:
        print(
            client.close_tasks(
                instance=config.INSTANCE_ID, project=config.TURBINIA_PROJECT,
                region=region, request_id=args.request_id, task_id=args.task_id,
                user=args.user, requester=getpass.getuser()))
        sys.exit(0)
      else:
        log.info(
            '--close_tasks (-c) requires --user, --request_id, or/and --task_id'
        )
        sys.exit(1)

    if args.dump_json and (args.statistics or args.requests or args.workers):
      log.info(
          'The --dump_json flag is not compatible with --statistics, '
          '--reqeusts, or --workers flags')
      sys.exit(1)

    if args.statistics:
      print(
          client.format_task_statistics(
              instance=config.INSTANCE_ID, project=config.TURBINIA_PROJECT,
              region=region, days=args.days_history, task_id=args.task_id,
              request_id=args.request_id, user=args.user, csv=args.csv))
      sys.exit(0)

    if args.wait and args.request_id:
      client.wait_for_request(
          instance=config.INSTANCE_ID, project=config.TURBINIA_PROJECT,
          region=region, request_id=args.request_id, user=args.user,
          poll_interval=args.poll_interval)
    elif args.wait and not args.request_id:
      log.info(
          '--wait requires --request_id, which is not specified. '
          'turbiniactl will exit without waiting.')

    if args.requests:
      print(
          client.format_request_status(
              instance=config.INSTANCE_ID, project=config.TURBINIA_PROJECT,
              region=region, days=args.days_history,
              all_fields=args.all_fields))
      sys.exit(0)

    if args.workers:
      print(
          client.format_worker_status(
              instance=config.INSTANCE_ID, project=config.TURBINIA_PROJECT,
              region=region, days=args.days_history,
              all_fields=args.all_fields))
      sys.exit(0)

    if args.dump_json:
      output_json = True
    else:
      output_json = False
    print(
        client.format_task_status(
            instance=config.INSTANCE_ID, project=config.TURBINIA_PROJECT,
            region=region, days=args.days_history, task_id=args.task_id,
            request_id=args.request_id, group_id=args.group_id, user=args.user,
            all_fields=args.all_fields, full_report=args.full_report,
            priority_filter=args.priority_filter, output_json=output_json))
    sys.exit(0)
  elif args.command == 'listjobs':
    log.info('Available Jobs:')
    client.list_jobs()
  elif args.command == 'gcplogs':
    if not config.STACKDRIVER_LOGGING:
      msg = 'Stackdriver logging must be enabled in order to use this.'
      raise TurbiniaException(msg)
    if args.output_dir and not os.path.isdir(args.output_dir):
      msg = 'Please provide a valid directory path.'
      raise TurbiniaException(msg)
    query = None
    if args.query:
      query = args.query
    if args.worker_logs:
      if query:
        query = 'jsonPayload.origin="psqworker" {0:s}'.format(query)
      else:
        query = 'jsonPayload.origin="psqworker"'
    if args.server_logs:
      if query:
        query = 'jsonPayload.origin="server" {0:s}'.format(query)
      else:
        query = 'jsonPayload.origin="server"'
    google_cloud.get_logs(
        config.TURBINIA_PROJECT, args.output_dir, args.days_history, query)
  elif args.command == 'dumpgcs':
    if not config.GCS_OUTPUT_PATH and not args.bucket:
      msg = 'GCS storage must be enabled in order to use this.'
      raise TurbiniaException(msg)
    if not args.task_id and not args.request_id:
      msg = 'You must specify one of task_id or request_id.'
      raise TurbiniaException(msg)
    if not os.path.isdir(args.output_dir):
      msg = 'Please provide a valid directory path.'
      raise TurbiniaException(msg)

    gcs_bucket = args.bucket if args.bucket else config.GCS_OUTPUT_PATH
    instance_id = args.instance_id if args.instance_id else config.INSTANCE_ID

    try:
      task_data = client.get_task_data(
          instance=instance_id, days=args.days_history,
          project=config.TURBINIA_PROJECT, region=config.TURBINIA_REGION,
          task_id=args.task_id, request_id=args.request_id,
          function_name='gettasks')
      output_writer = GCSOutputWriter(
          gcs_bucket, local_output_dir=args.output_dir)
      if not task_data:
        msg = 'No Tasks found for task/request ID'
        raise TurbiniaException(msg)
      if args.task_id:
        log.info(
            'Downloading GCS files for task_id {0:s} to {1:s}.'.format(
                args.task_id, args.output_dir))
        for task in task_data:
          if task['id'] == args.task_id:
            if task['saved_paths']:
              output_writer.copy_from_gcs(task['saved_paths'])
      if args.request_id:
        log.info(
            'Downloading GCS files for request_id {0:s} to {1:s}.'.format(
                args.request_id, args.output_dir))
        paths = []
        for task in task_data:
          if task['saved_paths']:
            paths.extend(task['saved_paths'])
        output_writer.copy_from_gcs(paths)

    except TurbiniaException as exception:
      log.error('Failed to pull the data {0!s}'.format(exception))
  else:
    log.warning('Command {0!s} not implemented.'.format(args.command))


# TODO: shard this function and move some of its functionalities to other files
# (move some  of this to evidence.py to run the checks etc)
def process_evidence(
    client, group_id, args=None, browser_type=None, disk_name=None,
    embedded_path=None, filter_patterns=None, format=None, mount_partition=None,
    name=None, profile=None, project=None, source=None, source_path=None,
    yara_rules=None, zone=None):
  """Creates evidence and turbinia request.
  
  Args:
    client(TurbiniaClient): TurbiniaClient used for creating requests.
    group_id(str): Group ID used for bulk processing.
    args(Namespace): commandline args.
    browser_type(str): Browser type used for hindsight.
    disk_name(str): Disk name used for processing cloud evidence.
    embedded_path(str): Embedded path for clouddiskembedded.
    filter_pattern(str): Filter patterns used for processing evidence.
    format(str): Output format for hindsight.
    mount_partition(int): Mount partition for clouddiskembedded.
    name(str): Evidence name.
    profile(list(str)): List of volatility profiles used for rawmemory.
    project(str): Project for cloud related evidence.
    source(str): Source for evidence.
    source_path(str): Source path used for host evidence.
    yara_rules(str): Yara rule for processing evidence.
    zone(str): Could zone used for cloud evidence. 
    """
  from turbinia import evidence

  # Set request id
  request_id = args.request_id if args.request_id else uuid.uuid4().hex

  # Start Evidence configuration
  evidence_ = None

  if args.command == 'rawdisk':
    evidence_ = evidence.RawDisk(
        name=name, source_path=os.path.abspath(source_path), source=source)
  elif args.command == 'directory':
    source_path = os.path.abspath(source_path)
    if not config.SHARED_FILESYSTEM:
      log.info(
          'A Cloud Only Architecture has been detected. '
          'Compressing the directory for GCS upload.')
      source_path = archive.CompressDirectory(
          source_path, output_path=config.TMP_DIR)
      evidence_ = evidence.CompressedDirectory(
          name=name, source_path=source_path, source=source)
    else:
      evidence_ = evidence.Directory(
          name=name, source_path=source_path, source=source)
  elif args.command == 'compresseddirectory':
    archive.ValidateTarFile(source_path)
    evidence_ = evidence.CompressedDirectory(
        name=name, source_path=os.path.abspath(source_path), source=source)
  elif args.command == 'googleclouddisk':
    evidence_ = evidence.GoogleCloudDisk(
        name=name, disk_name=disk_name, project=project, zone=zone,
        source=source)
  elif args.command == 'googleclouddiskembedded':
    parent_evidence_ = evidence.GoogleCloudDisk(
        name=name, disk_name=disk_name, project=project, source=source,
        mount_partition=mount_partition, zone=zone)
    evidence_ = evidence.GoogleCloudDiskRawEmbedded(
        name=name, disk_name=disk_name, project=project, zone=zone,
        embedded_path=embedded_path)
    evidence_.set_parent(parent_evidence_)
  elif args.command == 'hindsight':
    if format not in ['xlsx', 'sqlite', 'jsonl']:
      msg = 'Invalid output format.'
      raise TurbiniaException(msg)
    if browser_type not in ['Chrome', 'Brave']:
      msg = 'Browser type not supported.'
      raise TurbiniaException(msg)
    source_path = os.path.abspath(source_path)
    evidence_ = evidence.ChromiumProfile(
        name=name, source_path=source_path, output_format=format,
        browser_type=browser_type)
  elif args.command == 'rawmemory':
    source_path = os.path.abspath(source_path)
    evidence_ = evidence.RawMemory(
        name=name, source_path=source_path, profile=profile,
        module_list=args.module_list)

  if evidence_ and not args.force_evidence:
    if not config.SHARED_FILESYSTEM and evidence_.copyable:
      if os.path.exists(evidence_.local_path):
        output_manager = OutputManager()
        output_manager.setup(evidence_.type, request_id, remote_only=True)
        output_manager.save_evidence(evidence_)
      else:
        msg = (
            'The evidence local path does not exist: {0:s}. Please submit '
            'a new Request with a valid path.'.format(evidence_.local_path))
        raise TurbiniaException(msg)
    elif not config.SHARED_FILESYSTEM and not evidence_.cloud_only:
      msg = (
          'The evidence type {0:s} cannot run on Cloud instances of '
          'Turbinia. Consider wrapping it in a '
          'GoogleCloudDiskRawEmbedded or other Cloud compatible '
          'object'.format(evidence_.type))
      raise TurbiniaException(msg)

  request = None
  if evidence_:
    request = client.create_request(
        request_id=request_id, group_id=group_id, requester=getpass.getuser())
    request.evidence.append(evidence_)

    if args.decryption_keys:
      for credential in args.decryption_keys:
        try:
          credential_type, credential_data = credential.split('=')
        except ValueError as exception:
          msg = (
              'Could not parse credential [{0:s}] from decryption keys '
              '{1!s}: {2!s}'.format(
                  credential, args.decryption_keys, exception))
          raise TurbiniaException(msg)
        evidence_.credentials.append((credential_type, credential_data))

    # Recipe pre-condition checks.
    if args.recipe and args.recipe_path:
      msg = ('Expected a recipe name (-I) or path (-P) but found both.')
      raise TurbiniaException(msg)

    if args.recipe or args.recipe_path:
      # Load the specified recipe.
      recipe_dict = client.create_recipe(
          debug_tasks=args.debug_tasks, filter_patterns=filter_patterns,
          group_id=group_id, jobs_allowlist=args.jobs_allowlist,
          jobs_denylist=args.jobs_denylist,
          recipe_name=args.recipe if args.recipe else args.recipe_path,
          sketch_id=None, skip_recipe_validation=args.skip_recipe_validation,
          yara_rules=yara_rules)
      request.recipe = recipe_dict

    if args.dump_json:
      print(request.to_json().encode('utf-8'))
      sys.exit(0)
    else:
      log.info(
          'Creating request {0:s} with group id {1:s} and evidence '
          '{2:s}'.format(request.request_id, request.group_id, evidence_.name))
      # TODO add a new log line when group status is implemented
      log.info(
          'Run command "turbiniactl status -r {0:s}" to see the status of'
          ' this request and associated tasks'.format(request.request_id))
      client.send_request(request)

    if args.wait:
      log.info(
          'Waiting for request {0:s} to complete'.format(request.request_id))
      region = config.TURBINIA_REGION
      client.wait_for_request(
          instance=config.INSTANCE_ID, project=config.TURBINIA_PROJECT,
          region=region, request_id=request.request_id,
          poll_interval=args.poll_interval)
      print(
          client.format_task_status(
              instance=config.INSTANCE_ID, project=config.TURBINIA_PROJECT,
              region=region, request_id=request.request_id,
              all_fields=args.all_fields))


def main():
  """Main function for turbiniactl"""
  try:
    process_args(sys.argv[1:])
  except TurbiniaException as e:
    log.error('There was a problem processing arguments: {0:s}'.format(str(e)))
    sys.exit(1)
  log.info('Done.')
  sys.exit(0)


if __name__ == '__main__':
  main()
