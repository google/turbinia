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

from turbinia import config
from turbinia.config import logger
from turbinia.lib import libcloudforensics
from turbinia import __version__
from turbinia.processors import archive

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


def main():
  """Main function for turbiniactl"""
  # TODO(aarontp): Allow for single run mode when
  # by specifying evidence which will also terminate the task manager after
  # evidence has been processed.
  parser = argparse.ArgumentParser()
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
      '-C', '--recipe_config', help='Recipe configuration data passed in as '
      'comma separated key=value pairs (e.g. '
      '"-C key=value,otherkey=othervalue").  These will get passed to tasks '
      'as evidence config, and will also be written to the metadata.json file '
      'for Evidence types that write it', default=[], type=csv_list)
  parser.add_argument(
      '-f', '--force_evidence', action='store_true',
      help='Force evidence processing request in potentially unsafe conditions',
      required=False)
  parser.add_argument('-o', '--output_dir', help='Directory path for output')
  parser.add_argument('-L', '--log_file', help='Log file')
  parser.add_argument(
      '-r', '--request_id', help='Create new requests with this Request ID',
      required=False)
  parser.add_argument(
      '-R', '--run_local', action='store_true',
      help='Run completely locally without any server or other infrastructure. '
      'This can be used to run one-off Tasks to process data locally.')
  parser.add_argument(
      '-S', '--server', action='store_true',
      help='Run Turbinia Server indefinitely')
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
      '-j', '--jobs_whitelist', default=[], type=csv_list,
      help='A whitelist for Jobs that will be allowed to run (in CSV format, '
      'no spaces). This will not force them to run if they are not configured '
      'to. This is applied both at server start time and when the client makes '
      'a processing request. When applied at server start time the change is '
      'persistent while the server is running.  When applied by the client, it '
      'will only affect that processing request.')
  parser.add_argument(
      '-J', '--jobs_blacklist', default=[], type=csv_list,
      help='A blacklist for Jobs we will not allow to run.  See '
      '--jobs_whitelist help for details on format and when it is applied.')
  parser.add_argument(
      '-p', '--poll_interval', default=60, type=int,
      help='Number of seconds to wait between polling for task state info')
  parser.add_argument(
      '-t', '--task',
      help='The name of a single Task to run locally (must be used with '
      '--run_local.')
  parser.add_argument(
      '-w', '--wait', action='store_true',
      help='Wait to exit until all tasks for the given request have completed')

  subparsers = parser.add_subparsers(
      dest='command', title='Commands', metavar='<command>')

  # Action for printing config
  parser_config = subparsers.add_parser('config', help='Print out config file')
  parser_config.add_argument(
      '-f', '--file_only', action='store_true', help='Print out file path only')

  # TODO(aarontp): Find better way to specify these that allows for multiple
  # pieces of evidence to be submitted. Maybe automagically create different
  # commands based on introspection of evidence objects?
  # RawDisk
  parser_rawdisk = subparsers.add_parser(
      'rawdisk', help='Process RawDisk as Evidence')
  parser_rawdisk.add_argument(
      '-l', '--local_path', help='Local path to the evidence', required=True)
  parser_rawdisk.add_argument(
      '-P', '--mount_partition', default=1, type=int,
      help='The partition number to use when mounting this disk.  Defaults to '
      'the entire raw disk.  Only affects mounting, and not what gets '
      'processed.')
  parser_rawdisk.add_argument(
      '-s', '--source', help='Description of the source of the evidence',
      required=False)
  parser_rawdisk.add_argument(
      '-n', '--name', help='Descriptive name of the evidence', required=False)

  # Parser options for APFS Disk Evidence type
  parser_apfs = subparsers.add_parser(
      'apfs', help='Process APFSEncryptedDisk as Evidence')
  parser_apfs.add_argument(
      '-l', '--local_path', help='Local path to the encrypted APFS evidence',
      required=True)
  parser_apfs.add_argument(
      '-r', '--recovery_key', help='Recovery key for the APFS evidence.  '
      'Either recovery key or password must be specified.', required=False)
  parser_apfs.add_argument(
      '-p', '--password', help='Password for the APFS evidence.  '
      'If a recovery key is specified concurrently, password will be ignored.',
      required=False)
  parser_apfs.add_argument(
      '-s', '--source', help='Description of the source of the evidence',
      required=False)
  parser_apfs.add_argument(
      '-n', '--name', help='Descriptive name of the evidence', required=False)

  # Parser options for Bitlocker Disk Evidence type
  parser_bitlocker = subparsers.add_parser(
      'bitlocker', help='Process Bitlocker Disk as Evidence')
  parser_bitlocker.add_argument(
      '-l', '--local_path',
      help='Local path to the encrypted Bitlocker evidence', required=True)
  parser_bitlocker.add_argument(
      '-r', '--recovery_key', help='Recovery key for the Bitlocker evidence.  '
      'Either recovery key or password must be specified.', required=False)
  parser_bitlocker.add_argument(
      '-p', '--password', help='Password for the Bitlocker evidence.  '
      'If a recovery key is specified concurrently, password will be ignored.',
      required=False)
  parser_bitlocker.add_argument(
      '-s', '--source', help='Description of the source of the evidence',
      required=False)
  parser_bitlocker.add_argument(
      '-n', '--name', help='Descriptive name of the evidence', required=False)

  # Parser options for Google Cloud Disk Evidence type
  parser_googleclouddisk = subparsers.add_parser(
      'googleclouddisk',
      help='Process Google Cloud Persistent Disk as Evidence')
  parser_googleclouddisk.add_argument(
      '-C', '--copy_only', action='store_true', help='Only copy disk and do '
      'not process with Turbinia. This only takes effect when a source '
      '--project is defined and can be run without any Turbinia server or '
      'workers configured.')
  parser_googleclouddisk.add_argument(
      '-d', '--disk_name', help='Google Cloud name for disk', required=True)
  parser_googleclouddisk.add_argument(
      '-p', '--project', help='Project that the disk to process is associated '
      'with. If this is different from the project that Turbinia is running '
      'in, it will be copied to the Turbinia project.')
  parser_googleclouddisk.add_argument(
      '-P', '--mount_partition', default=0, type=int,
      help='The partition number to use when mounting this disk.  Defaults to '
      'the entire raw disk.  Only affects mounting, and not what gets '
      'processed.')
  parser_googleclouddisk.add_argument(
      '-z', '--zone', help='Geographic zone the disk exists in')
  parser_googleclouddisk.add_argument(
      '-s', '--source', help='Description of the source of the evidence',
      required=False)
  parser_googleclouddisk.add_argument(
      '-n', '--name', help='Descriptive name of the evidence', required=False)

  # Parser options for Google Cloud Persistent Disk Embedded Raw Image
  parser_googleclouddiskembedded = subparsers.add_parser(
      'googleclouddiskembedded',
      help='Process Google Cloud Persistent Disk with an embedded raw disk '
      'image as Evidence')
  parser_googleclouddiskembedded.add_argument(
      '-C', '--copy_only', action='store_true', help='Only copy disk and do '
      'not process with Turbinia. This only takes effect when a source '
      '--project is defined and can be run without any Turbinia server or '
      'workers configured.')
  parser_googleclouddiskembedded.add_argument(
      '-e', '--embedded_path',
      help='Path within the Persistent Disk that points to the raw image file',
      required=True)
  parser_googleclouddiskembedded.add_argument(
      '-d', '--disk_name', help='Google Cloud name for disk', required=True)
  parser_googleclouddiskembedded.add_argument(
      '-p', '--project', help='Project that the disk to process is associated '
      'with. If this is different from the project that Turbinia is running '
      'in, it will be copied to the Turbinia project.')
  parser_googleclouddiskembedded.add_argument(
      '-P', '--mount_partition', default=0, type=int,
      help='The partition number to use when mounting this disk.  Defaults to '
      'the entire raw disk.  Only affects mounting, and not what gets '
      'processed.')
  parser_googleclouddiskembedded.add_argument(
      '-z', '--zone', help='Geographic zone the disk exists in')
  parser_googleclouddiskembedded.add_argument(
      '-s', '--source', help='Description of the source of the evidence',
      required=False)
  parser_googleclouddiskembedded.add_argument(
      '-n', '--name', help='Descriptive name of the evidence', required=False)

  # RawMemory
  parser_rawmemory = subparsers.add_parser(
      'rawmemory', help='Process RawMemory as Evidence')
  parser_rawmemory.add_argument(
      '-l', '--local_path', help='Local path to the evidence', required=True)
  parser_rawmemory.add_argument(
      '-P', '--profile', help='Profile to use with Volatility', required=True)
  parser_rawmemory.add_argument(
      '-n', '--name', help='Descriptive name of the evidence', required=False)
  parser_rawmemory.add_argument(
      '-m', '--module_list', type=csv_list,
      help='Volatility module(s) to execute', required=True)

  # Parser options for Directory evidence type
  parser_directory = subparsers.add_parser(
      'directory', help='Process a directory as Evidence')
  parser_directory.add_argument(
      '-l', '--local_path', help='Local path to the evidence', required=True)
  parser_directory.add_argument(
      '-s', '--source', help='Description of the source of the evidence',
      required=False)
  parser_directory.add_argument(
      '-n', '--name', help='Descriptive name of the evidence', required=False)

  # Parser options for CompressedDirectory evidence type
  parser_compressed_directory = subparsers.add_parser(
      'compressedirectory', help='Process a compressed tar file as Evidence')
  parser_compressed_directory.add_argument(
      '-l', '--local_path', help='Local path to the evidence', required=True)
  parser_compressed_directory.add_argument(
      '-s', '--source', help='Description of the source of the evidence',
      required=False)
  parser_compressed_directory.add_argument(
      '-n', '--name', help='Descriptive name of the evidence', required=False)

  # Parser options for ChromiumProfile evidence type
  parser_hindsight = subparsers.add_parser(
      'hindsight', help='Process ChromiumProfile as Evidence')
  parser_hindsight.add_argument(
      '-l', '--local_path', help='Local path to the evidence', required=True)
  parser_hindsight.add_argument(
      '-f', '--format', help='Output format (supported types are '
      'xlsx, sqlite, jsonl)', default='sqlite')
  parser_hindsight.add_argument(
      '-b', '--browser_type', help='The type of browser the input files belong'
      'to (supported types are Chrome, Brave)', default='Chrome')
  parser_hindsight.add_argument(
      '-n', '--name', help='Descriptive name of the evidence', required=False)

  # List Jobs
  subparsers.add_parser(
      'listjobs',
      help='List all available Jobs. These Job names can be used by '
      '--jobs_whitelist and --jobs_blacklist')

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
      '-f', '--force', help='Gatekeeper for --close_tasks', action='store_true',
      required=False)
  parser_status.add_argument(
      '-r', '--request_id', help='Show tasks with this Request ID',
      required=False)
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
      '-t', '--task_id', help='Show task for given Task ID', required=False)
  parser_status.add_argument(
      '-u', '--user', help='Show task for given user', required=False)

  # Server
  subparsers.add_parser('server', help='Run Turbinia Server')

  args = parser.parse_args()

  # Load the config before final logger setup so we can the find the path to the
  # log file.
  if args.config_file:
    config.LoadConfig(config_file=args.config_file)
  else:
    config.LoadConfig()
  if args.log_file:
    config.LOG_FILE = args.log_file
  if args.output_dir:
    config.OUTPUT_DIR = args.output_dir

  # Run logger setup again to get file-handler now that we have the logfile path
  # from the config.
  logger.setup()
  if args.quiet:
    log.setLevel(logging.ERROR)
  elif args.debug:
    log.setLevel(logging.DEBUG)
  else:
    log.setLevel(logging.INFO)

  log.info('Turbinia version: {0:s}'.format(__version__))

  # Do late import of other needed Turbinia modules.  This is needed because the
  # config is loaded by these modules at load time, and we want to wait to load
  # the config until after we parse the args so that we can use those arguments
  # to point to config paths.
  from turbinia.client import TurbiniaClient
  from turbinia.client import TurbiniaCeleryClient
  from turbinia.client import TurbiniaServer
  from turbinia.client import TurbiniaCeleryWorker
  from turbinia.client import TurbiniaPsqWorker
  from turbinia import evidence
  from turbinia.message import TurbiniaRequest

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
      log.info(
          "Failed to read config file {0:s}: {1!s}".format(
              config.configSource, exception))
      sys.exit(1)

  if args.jobs_whitelist and args.jobs_blacklist:
    log.error(
        'A Job filter whitelist and blacklist cannot be specified at the same '
        'time')
    sys.exit(1)

  # Read set set filter_patterns
  filter_patterns = None
  if (args.filter_patterns_file and
      not os.path.exists(args.filter_patterns_file)):
    log.error('Filter patterns file {0:s} does not exist.')
    sys.exit(1)
  elif args.filter_patterns_file:
    try:
      filter_patterns = open(args.filter_patterns_file).read().splitlines()
    except IOError as e:
      log.warning(
          'Cannot open file {0:s} [{1!s}]'.format(args.filter_patterns_file, e))

  # Create Client object
  if args.command not in ('psqworker', 'server'):
    if config.TASK_MANAGER.lower() == 'celery':
      client = TurbiniaCeleryClient()
    elif args.run_local:
      client = TurbiniaClient(run_local=True)
    else:
      client = TurbiniaClient()
  else:
    client = None

  # Make sure run_local flags aren't conflicting with other server/client flags
  server_flags_set = args.server or args.command == 'server'
  worker_flags_set = args.command in ('psqworker', 'celeryworker')
  if args.run_local and (server_flags_set or worker_flags_set):
    log.error('--run_local flag is not compatible with server/worker flags')
    sys.exit(1)

  if args.run_local and not args.task:
    log.error('--run_local flag requires --task flag')
    sys.exit(1)

  # Set zone/project to defaults if flags are not set, and also copy remote
  # disk if needed.
  if args.command in ('googleclouddisk', 'googleclouddiskrawembedded'):
    if not args.zone and config.TURBINIA_ZONE:
      args.zone = config.TURBINIA_ZONE
    elif not args.zone and not config.TURBINIA_ZONE:
      log.error('Turbinia zone must be set by --zone or in config')
      sys.exit(1)

    if not args.project and config.TURBINIA_PROJECT:
      args.project = config.TURBINIA_PROJECT
    elif not args.project and not config.TURBINIA_PROJECT:
      log.error('Turbinia project must be set by --project or in config')
      sys.exit(1)

    if ((args.project and args.project != config.TURBINIA_PROJECT) or
        (args.zone and args.zone != config.TURBINIA_ZONE)):
      new_disk = libcloudforensics.create_disk_copy(
          args.project, config.TURBINIA_PROJECT, None, config.TURBINIA_ZONE,
          args.disk_name)
      args.disk_name = new_disk.name
      if args.copy_only:
        log.info('--copy_only specified, so not processing with Turbinia')
        sys.exit(0)

  # Start Evidence configuration
  evidence_ = None
  if args.command == 'rawdisk':
    args.name = args.name if args.name else args.local_path
    local_path = os.path.abspath(args.local_path)
    evidence_ = evidence.RawDisk(
        name=args.name, local_path=local_path,
        mount_partition=args.mount_partition, source=args.source)
  elif args.command == 'apfs':
    if not args.password and not args.recovery_key:
      log.error('Neither recovery key nor password is specified.')
      sys.exit(1)
    args.name = args.name if args.name else args.local_path
    local_path = os.path.abspath(args.local_path)
    evidence_ = evidence.APFSEncryptedDisk(
        name=args.name, local_path=local_path, recovery_key=args.recovery_key,
        password=args.password, source=args.source)
  elif args.command == 'bitlocker':
    if not args.password and not args.recovery_key:
      log.error('Neither recovery key nor password is specified.')
      sys.exit(1)
    args.name = args.name if args.name else args.local_path
    local_path = os.path.abspath(args.local_path)
    evidence_ = evidence.BitlockerDisk(
        name=args.name, local_path=local_path, recovery_key=args.recovery_key,
        password=args.password, source=args.source)
  elif args.command == 'directory':
    args.name = args.name if args.name else args.local_path
    local_path = os.path.abspath(args.local_path)
    evidence_ = evidence.Directory(
        name=args.name, local_path=local_path, source=args.source)
  elif args.command == 'compressedirectory':
    archive.ValidateTarFile(args.source_path)
    args.name = args.name if args.name else args.source_path
    source_path = os.path.abspath(args.source_path)
    evidence_ = evidence.CompressedDirectory(
        name=args.name, source_path=source_path, source=args.source)
  elif args.command == 'googleclouddisk':
    args.name = args.name if args.name else args.disk_name
    evidence_ = evidence.GoogleCloudDisk(
        name=args.name, disk_name=args.disk_name, project=args.project,
        mount_partition=args.mount_partition, zone=args.zone,
        source=args.source)
  elif args.command == 'googleclouddiskembedded':
    args.name = args.name if args.name else args.disk_name
    evidence_ = evidence.GoogleCloudDiskRawEmbedded(
        name=args.name, disk_name=args.disk_name,
        embedded_path=args.embedded_path, mount_partition=args.mount_partition,
        project=args.project, zone=args.zone, source=args.source)
  elif args.command == 'hindsight':
    if args.format not in ['xlsx', 'sqlite', 'jsonl']:
      log.error('Invalid output format.')
      sys.exit(1)
    if args.browser_type not in ['Chrome', 'Brave']:
      log.error('Browser type not supported.')
      sys.exit(1)
    args.name = args.name if args.name else args.local_path
    local_path = os.path.abspath(args.local_path)
    evidence_ = evidence.ChromiumProfile(
        name=args.name, local_path=local_path, output_format=args.format,
        browser_type=args.browser_type)
  elif args.command == 'rawmemory':
    args.name = args.name if args.name else args.local_path
    local_path = os.path.abspath(args.local_path)
    evidence_ = evidence.RawMemory(
        name=args.name, local_path=local_path, profile=args.profile,
        module_list=args.module_list)
  elif args.command == 'psqworker':
    # Set up root logger level which is normally set by the psqworker command
    # which we are bypassing.
    logger.setup()
    worker = TurbiniaPsqWorker()
    worker.start()
  elif args.command == 'celeryworker':
    logger.setup()
    worker = TurbiniaCeleryWorker()
    worker.start()
  elif args.command == 'server':
    server = TurbiniaServer(
        jobs_blacklist=args.jobs_blacklist, jobs_whitelist=args.jobs_whitelist)
    server.start()
  elif args.command == 'status':
    region = config.TURBINIA_REGION
    if args.close_tasks:
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

    print(
        client.format_task_status(
            instance=config.INSTANCE_ID, project=config.TURBINIA_PROJECT,
            region=region, days=args.days_history, task_id=args.task_id,
            request_id=args.request_id, user=args.user,
            all_fields=args.all_fields, full_report=args.full_report,
            priority_filter=args.priority_filter))
  elif args.command == 'listjobs':
    log.info('Available Jobs:')
    client.list_jobs()
  else:
    log.warning('Command {0!s} not implemented.'.format(args.command))

  if evidence_ and not args.force_evidence:
    if config.SHARED_FILESYSTEM and evidence_.cloud_only:
      log.error(
          'The evidence type {0:s} is Cloud only, and this instance of '
          'Turbinia is not a cloud instance.'.format(evidence_.type))
      sys.exit(1)
    elif not config.SHARED_FILESYSTEM and not evidence_.cloud_only:
      log.error(
          'The evidence type {0:s} cannot run on Cloud instances of '
          'Turbinia. Consider wrapping it in a '
          'GoogleCloudDiskRawEmbedded or other Cloud compatible '
          'object'.format(evidence_.type))
      sys.exit(1)

  # If we have evidence to process and we also want to run as a server, then
  # we'll just process the evidence directly rather than send it through the
  # PubSub frontend interface.  If we're not running as a server then we will
  # create a new TurbiniaRequest and send it over PubSub.
  request = None
  if evidence_ and args.server:
    server = TurbiniaServer()
    server.add_evidence(evidence_)
    server.start()
  elif evidence_:
    request = TurbiniaRequest(
        request_id=args.request_id, requester=getpass.getuser())
    request.evidence.append(evidence_)
    if filter_patterns:
      request.recipe['filter_patterns'] = filter_patterns
    if args.jobs_blacklist:
      request.recipe['jobs_blacklist'] = args.jobs_blacklist
    if args.jobs_whitelist:
      request.recipe['jobs_whitelist'] = args.jobs_whitelist
    if args.recipe_config:
      for pair in args.recipe_config:
        try:
          key, value = pair.split('=')
        except ValueError as exception:
          log.error(
              'Could not parse key=value pair [{0:s}] from recipe config '
              '{1!s}: {2!s}'.format(pair, args.recipe_config, exception))
          sys.exit(1)
        request.recipe[key] = value
    if args.dump_json:
      print(request.to_json().encode('utf-8'))
      sys.exit(0)
    else:
      log.info(
          'Creating request {0:s} with evidence {1:s}'.format(
              request.request_id, evidence_.name))
      log.info(
          'Run command "turbiniactl status -r {0:s}" to see the status of'
          ' this request and associated tasks'.format(request.request_id))
      if not args.run_local:
        client.send_request(request)
      else:
        log.debug('--run_local specified so not sending request to server')

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

  if args.run_local and not evidence_:
    log.error('Evidence must be specified if using --run_local')
    sys.exit(1)
  if args.run_local and evidence_.cloud_only:
    log.error('--run_local cannot be used with Cloud only Evidence types')
    sys.exit(1)
  if args.run_local and evidence_:
    result = client.run_local_task(args.task, request)
    log.info('Task execution result: {0:s}'.format(result))

  log.info('Done.')
  sys.exit(0)


if __name__ == '__main__':
  main()
