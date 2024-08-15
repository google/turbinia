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
"""Turbinia API client command-line tool."""

import os
import logging
import click
import tarfile

from importlib.metadata import version as importlib_version

from turbinia_api_lib import exceptions
from turbinia_api_lib import api_client
from turbinia_api_lib import models
from turbinia_api_lib.api import turbinia_requests_api
from turbinia_api_lib.api import turbinia_tasks_api
from turbinia_api_lib.api import turbinia_configuration_api
from turbinia_api_lib.api import turbinia_jobs_api
from turbinia_api_lib.api import turbinia_request_results_api
from turbinia_api_lib.api import turbinia_evidence_api
from turbinia_api_lib.api import turbinia_logs_api
from turbinia_client.core import groups
from turbinia_client.helpers import formatter

log = logging.getLogger(__name__)


@groups.config_group.command('list')
@click.pass_context
def get_config(ctx: click.Context) -> None:
  """Gets Turbinia server configuration."""
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_configuration_api.TurbiniaConfigurationApi(client)
  try:
    api_response = api_instance.read_config_with_http_info()
    decoded_response = formatter.decode_api_response(api_response)
    formatter.echo_json(decoded_response)
  except exceptions.ApiException as exception:
    log.error(
        f'Received status code {exception.status} '
        f'when calling read_config_with_http_info: {exception.body}')


@groups.config_group.command('version')
@click.pass_context
def get_api_server_version(ctx: click.Context) -> None:
  """Gets Turbinia API server version."""
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_configuration_api.TurbiniaConfigurationApi(client)
  try:
    api_response = api_instance.get_version()
    decoded_response = formatter.decode_api_response(api_response)
    formatter.echo_json(decoded_response)
  except exceptions.ApiException as exception:
    log.error(
        f'Received status code {exception.status} '
        f'when calling get_version: {exception.body}')


@groups.config_group.command('download')
@click.pass_context
def get_config_download(ctx: click.Context) -> None:
  """Downloads current Turbinia config from the API server."""
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_configuration_api.TurbiniaConfigurationApi(client)
  try:
    api_response = api_instance.download_config()
    click.echo(api_response)
  except exceptions.ApiException as exception:
    log.error(
        f'Received status code {exception.status} '
        f'when calling download_config: {exception.body}')


@groups.result_group.command('request')
@click.pass_context
@click.argument('request_id')
def get_request_result(ctx: click.Context, request_id: str) -> None:
  """Gets Turbinia request results / output files."""
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_request_results_api.TurbiniaRequestResultsApi(client)
  filename = f'{request_id}.tgz'
  click.echo(f'Downloading output for request {request_id} to: {filename}')
  try:
    api_response = api_instance.get_request_output_with_http_info(
        request_id, _preload_content=False, _request_timeout=(30, 900))
    # Read the response and save into a local file.
    with open(filename, 'wb') as file:
      file.write(api_response.raw_data)
  except exceptions.ApiException as exception:
    log.error(
        f'Received status code {exception.status} '
        f'when calling get_request_output_with_http_info: {exception.body}')
  except OSError as exception:
    log.error(f'Unable to save file: {exception}')
  except (ValueError, tarfile.ReadError, tarfile.CompressionError) as exception:
    log.error(f'Error reading saved results file {filename}: {exception}')


@groups.result_group.command('task')
@click.pass_context
@click.argument('task_id')
def get_task_result(ctx: click.Context, task_id: str) -> None:
  """Gets Turbinia task results / output files."""
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_request_results_api.TurbiniaRequestResultsApi(client)
  filename = f'{task_id}.tgz'
  click.echo(f'Downloading output for task {task_id} to: {filename}')
  try:
    api_response = api_instance.get_task_output_with_http_info(
        task_id, _preload_content=False, _request_timeout=(30, 900))
    # Read the response and save into a local file.
    with open(filename, 'wb') as file:
      file.write(api_response.raw_data)
  except exceptions.ApiException as exception:
    log.error(
        f'Received status code {exception.status} '
        f'when calling get_task_output_with_http_info: {exception.body}')
  except OSError as exception:
    log.error(f'Unable to save file: {exception}')
  except (ValueError, tarfile.ReadError, tarfile.CompressionError) as exception:
    log.error(f'Error reading saved results file {filename}: {exception}')


@groups.result_group.command('plasofile')
@click.pass_context
@click.argument('task_id')
def get_plaso_file(ctx: click.Context, task_id: str) -> None:
  """Gets Turbinia task results / output files."""
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_request_results_api.TurbiniaRequestResultsApi(client)
  filename = f'{task_id}.plaso'
  click.echo(f'Downloading output for task {task_id} to: {filename}')
  try:
    api_response = api_instance.get_plaso_file_with_http_info(
        task_id, _preload_content=False, _request_timeout=(30, 900))
    # Read the response and save into a local file.
    with open(filename, 'wb') as file:
      file.write(api_response.raw_data)
  except exceptions.ApiException as exception:
    log.error(
        f'Received status code {exception.status} '
        f'when calling get_plaso_file_with_http_info: {exception.body}')
  except OSError as exception:
    log.error(f'Unable to save file: {exception}')
  except (ValueError, tarfile.ReadError, tarfile.CompressionError) as exception:
    log.error(f'Error reading saved results file {filename}: {exception}')


@groups.jobs_group.command('list')
@click.pass_context
def get_jobs(ctx: click.Context) -> None:
  """Gets Turbinia jobs list."""
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_jobs_api.TurbiniaJobsApi(client)
  try:
    api_response = api_instance.read_jobs_with_http_info()
    decoded_response = formatter.decode_api_response(api_response)
    formatter.echo_json(decoded_response)
  except exceptions.ApiException as exception:
    log.error(
        f'Received status code {exception.status} '
        f'when calling read_jobs_with_http_info: {exception.body}')


@groups.status_group.command('request')
@click.pass_context
@click.argument('request_id')
@click.option(
    '--priority_filter', '-p', help='This sets what report sections are '
    'shown in full detail in report output.  Any tasks that have set a '
    'report_priority value equal to or lower than this setting will be '
    'shown in full detail, and tasks with a higher value will only have '
    'a summary shown.  The default is 20 which corresponds to "HIGH_PRIORITY"'
    'To see all tasks report output in full detail, set --priority_filter=100 '
    'or to see CRITICAL only set --priority_filter=10', show_default=True,
    default=20, type=int, required=False)
@click.option(
    '--show_all', '-a', help='Shows all fields including saved output paths.',
    is_flag=True, required=False)
@click.option(
    '--json_dump', '-j', help='Generates JSON output.', is_flag=True,
    required=False)
def get_request(
    ctx: click.Context, request_id: str, priority_filter: int, show_all: bool,
    json_dump: bool) -> None:
  """Gets Turbinia request status."""
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_requests_api.TurbiniaRequestsApi(client)
  if request_id == 'summary':
    click.echo(
        'Oops! "summary" is not a valid request identifier. '
        'Did you mean to run "turbinia-client status summary" instead?')
    return
  try:
    api_response = api_instance.get_request_status_with_http_info(request_id)
    decoded_response = formatter.decode_api_response(api_response)
    if json_dump:
      formatter.echo_json(decoded_response)
    else:
      report = formatter.RequestMarkdownReport(
          decoded_response).generate_markdown(
              priority_filter=priority_filter, show_all=show_all)
      click.echo(report)
  except exceptions.ApiException as exception:
    log.error(
        f'Received status code {exception.status} '
        f'when calling get_request_status_with_http_info: {exception.body}')


@groups.status_group.command('workers')
@click.pass_context
@click.option(
    '--days', '-d', help='Specifies status timeframe.', required=False)
@click.option(
    '--all_fields', '-a', help='Returns all fields.', is_flag=True,
    required=False)
@click.option(
    '--json_dump', '-j', help='Generates JSON output.', is_flag=True,
    required=False)
def get_workers(
    ctx: click.Context, days: int, all_fields: bool, json_dump: bool) -> None:
  """Shows Workers status information."""
  days = int(days) if days else 7
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_tasks_api.TurbiniaTasksApi(client)
  try:
    api_response = api_instance.get_workers_status_with_http_info(
        days, all_fields)
    decoded_response = formatter.decode_api_response(api_response)

    if json_dump:
      formatter.echo_json(decoded_response)
    else:
      report = formatter.WorkersMarkdownReport(decoded_response,
                                               days).generate_markdown()
      click.echo(report)
  except exceptions.ApiException as exception:
    log.error(
        f'Received status code {exception.status} '
        f'when calling get_workers_status_with_http_info: {exception.body}')


@groups.status_group.command('statistics')
@click.pass_context
@click.option(
    '--days', '-d', help='Specifies statistics timeframe.', required=False)
@click.option(
    '--task_id', '-t', help='Gets statistics for a specific task.',
    required=False)
@click.option(
    '--request_id', '-r', help='Gets statistics for a specific request.',
    required=False)
@click.option(
    '--user', '-u', help='Gets statistics for a specific user.', required=False)
@click.option(
    '--csv', '-c', help='Outputs statistics as CSV.', is_flag=True,
    required=False)
@click.option(
    '--json_dump', '-j', help='Generates JSON output.', is_flag=True,
    required=False)
def get_statistics(
    ctx: click.Context, days: int, task_id: str, request_id: str, user: str,
    csv: bool, json_dump: bool) -> None:
  """Shows statistics about tasks."""
  days = int(days) if days else 7
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_tasks_api.TurbiniaTasksApi(client)
  try:
    api_response = api_instance.get_task_statistics_with_http_info(
        days=days, task_id=task_id, request_id=request_id, user=user)
    decoded_response: models.CompleteTurbiniaStats = (
        formatter.decode_api_response(api_response))
    if json_dump:
      formatter.echo_json(decoded_response)
    else:
      stat_formatter = formatter.StatsMarkdownReport(decoded_response.dict())
      if csv:
        report = stat_formatter.generate_csv()
      else:
        report = stat_formatter.generate_markdown()
      click.echo(report)
  except exceptions.ApiException as exception:
    log.error(
        f'Received status code {exception.status} '
        f'when calling get_task_statistics_with_http_info: {exception.body}')


@groups.status_group.command('summary')
@click.pass_context
@click.option(
    '--json_dump', '-j', help='Generates JSON output.', is_flag=True,
    required=False)
def get_requests_summary(ctx: click.Context, json_dump: bool) -> None:
  """Gets a summary of all Turbinia requests."""
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_requests_api.TurbiniaRequestsApi(client)
  try:
    api_response = api_instance.get_requests_summary_with_http_info()
    decoded_response = formatter.decode_api_response(api_response)

    if json_dump:
      formatter.echo_json(decoded_response)
    else:
      report = formatter.SummaryMarkdownReport(
          decoded_response).generate_markdown()
      click.echo(report)
  except exceptions.ApiException as exception:
    log.error(
        f'Received status code {exception.status} '
        f'when calling get_requests_summary_with_http_info: {exception.body}')


@groups.status_group.command('task')
@click.pass_context
@click.argument('task_id')
@click.option(
    '--show_all', '-a', help='Shows all field regardless of priority.',
    is_flag=True, required=False)
@click.option(
    '--json_dump', '-j', help='Generates JSON output.', is_flag=True,
    required=False)
def get_task(
    ctx: click.Context, task_id: str, show_all: bool, json_dump: bool) -> None:
  """Gets Turbinia task status."""
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_tasks_api.TurbiniaTasksApi(client)
  try:
    api_response = api_instance.get_task_status_with_http_info(task_id)
    decoded_response = formatter.decode_api_response(api_response)
    if json_dump:
      formatter.echo_json(decoded_response)
    else:
      report = formatter.TaskMarkdownReport(decoded_response).generate_markdown(
          show_all=show_all, priority_filter=100)
      click.echo(report)
  except exceptions.ApiException as exception:
    log.error(
        f'Received status code {exception.status} '
        f'when calling get_task_status_with_http_info: {exception.body}')


@groups.evidence_group.command('summary')
@click.pass_context
@click.option(
    '--group', '-g', help='Attribute by which output will be grouped.',
    default=None, required=False)
@click.option(
    '--output', '-o', help='Type of output (keys | content | count).',
    default='keys', required=False)
@click.option(
    '--json_dump', '-j', help='Generates JSON output.', is_flag=True,
    required=False)
def get_evidence_summary(
    ctx: click.Context, group: str, output: str, json_dump: bool) -> None:
  """Gets Turbinia evidence summary."""
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_evidence_api.TurbiniaEvidenceApi(client)
  try:
    api_response = api_instance.get_evidence_summary_with_http_info(
        group, output)
    decoded_response = formatter.decode_api_response(api_response)

    if json_dump:
      formatter.echo_json(decoded_response)
    else:
      report = formatter.EvidenceSummaryMarkdownReport(
          decoded_response).generate_summary_markdown(output)
      click.echo(report)
  except exceptions.ApiException as exception:
    log.error(
        f'Received status code {exception.status} '
        f'when calling get_evidence_summary_with_http_info: {exception.body}')


@groups.evidence_group.command('query')
@click.pass_context
@click.argument('attribute_name')
@click.argument('attribute_value')
@click.option(
    '--output', '-o', help='Type of output (keys | content | count).',
    default='keys', is_flag=False, required=False)
@click.option(
    '--json_dump', '-j', help='Generates JSON output.', is_flag=True,
    required=False)
def query_evidence(
    ctx: click.Context, attribute_name: str, attribute_value: str, output: str,
    json_dump: bool) -> None:
  """Queries Turbinia evidence."""
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_evidence_api.TurbiniaEvidenceApi(client)
  try:
    api_response = api_instance.query_evidence_with_http_info(
        attribute_value, attribute_name, output)
    decoded_response = formatter.decode_api_response(api_response)

    if json_dump:
      formatter.echo_json(decoded_response)
    else:
      report = formatter.EvidenceSummaryMarkdownReport(
          decoded_response).generate_summary_markdown(output)
      click.echo(report)
  except exceptions.ApiException as exception:
    log.error(
        f'Received status code {exception.status} '
        f'when calling query_evidence_with_http_info: {exception.body}')


@groups.evidence_group.command('get')
@click.pass_context
@click.argument('evidence_id')
@click.option(
    '--show_all', '-a', help='Shows all evidence attributes.', is_flag=True,
    required=False)
@click.option(
    '--json_dump', '-j', help='Generates JSON output.', is_flag=True,
    required=False)
def get_evidence(
    ctx: click.Context, evidence_id: str, show_all: bool,
    json_dump: bool) -> None:
  """Get Turbinia evidence."""
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_evidence_api.TurbiniaEvidenceApi(client)
  try:
    api_response = api_instance.get_evidence_by_id_with_http_info(evidence_id)
    decoded_response = formatter.decode_api_response(api_response)

    if json_dump:
      formatter.echo_json(decoded_response)
    else:
      report = formatter.EvidenceMarkdownReport(
          decoded_response).generate_markdown(1, show_all=show_all)
      click.echo(report)
  except exceptions.ApiException as exception:
    log.error(
        f'Received status code {exception.status} '
        f'when calling get_evidence_by_id_with_http_info: {exception.body}')


@groups.evidence_group.command('upload')
@click.pass_context
@click.argument('ticket_id')
@click.option(
    '--path', '-p', help='Path of file or directory to be uploaded.',
    required=True, multiple=True)
@click.option(
    '--calculate_hash', '-c', help='Calculates file hash.', is_flag=True,
    required=False)
@click.option(
    '--json_dump', '-j', help='Generates JSON output.', is_flag=True,
    required=False)
def upload_evidence(
    ctx: click.Context, ticket_id: str, path: list, calculate_hash: bool,
    json_dump: bool) -> None:
  """Uploads evidence to Turbinia server."""
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance_config = turbinia_configuration_api.TurbiniaConfigurationApi(
      client)
  max_upload_size = api_instance_config.read_config()['API_MAX_UPLOAD_SIZE']
  api_instance = turbinia_evidence_api.TurbiniaEvidenceApi(client)
  files = []
  for current_path in path:
    if os.path.isfile(current_path):
      files.append(current_path)
      continue
    for file_name in os.listdir(current_path):
      file_path = os.path.join(current_path, file_name)
      if os.path.isfile(file_path):
        files.append(file_path)
  report = {}
  for file_path in files:
    try:
      size = os.path.getsize(file_path)
      if size > max_upload_size:
        error_message = (
            f'Unable to upload {size / (1024 ** 3)} GB file',
            f'{file_path} greater than {max_upload_size / (1024 ** 3)} GB')
        log.error(error_message)
        continue
      abs_path = os.path.abspath(file_path)
    except OSError:
      log.error(f'Unable to read file in {file_path}')
      continue
    try:
      api_response = api_instance.upload_evidence_with_http_info(
          [file_path], ticket_id, calculate_hash)
      report[abs_path] = formatter.decode_api_response(api_response)
    except exceptions.ApiException as exception:
      error_message = (
          f'Received status code {exception.status} '
          f'when calling upload_evidence_with_http_info: {exception}')
      log.error(error_message)
      report[abs_path] = error_message
  if json_dump:
    formatter.echo_json(report)
  else:
    report = '\n'.join(
        formatter.EvidenceMarkdownReport({}).dict_to_markdown(
            report, 0, format_keys=False))
    click.echo(report)


@click.command('version')
def version():
  """Returns the turbinia-client package distribution version."""
  cli_version = importlib_version('turbinia-client')
  click.echo(f'turbinia-client version {cli_version}')


@groups.report_group.command('request')
@click.pass_context
@click.argument('request_id')
def get_request_report(ctx: click.Context, request_id: str) -> None:
  """Gets Turbinia request Markdown report.
  
  This command will not do any filtering since this is provided in
  the `status request` command via --priority_filter

  """
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_requests_api.TurbiniaRequestsApi(client)
  try:
    api_response = api_instance.get_request_report(request_id)
    click.echo(api_response)
  except exceptions.ApiException as exception:
    log.error(
        f'Received status code {exception.status} '
        f'when calling get_request_report: {exception.body}')


@groups.report_group.command('task')
@click.pass_context
@click.argument('task_id')
def get_task_report(ctx: click.Context, task_id: str) -> None:
  """Gets Turbinia task Markdown report."""
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_tasks_api.TurbiniaTasksApi(client)
  try:
    api_response = api_instance.get_task_report(task_id)
    click.echo(api_response)
  except exceptions.ApiException as exception:
    log.error(
        f'Received status code {exception.status} '
        f'when calling get_request_report: {exception.body}')


@groups.logs_group.command('system')
@click.pass_context
@click.argument('hostname')
@click.option(
    '--num_lines', '-n', help='Maximum number of log lines to retrieve.',
    required=False, is_flag=False, default=500)
def get_logs(ctx: click.Context, hostname: str, num_lines: int) -> None:
  """Gets Turbinia system logs."""
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_logs_api.TurbiniaLogsApi(client)
  try:
    api_response = api_instance.get_turbinia_logs(hostname, num_lines)
    click.echo(api_response)
  except exceptions.ApiException as exception:
    log.error(
        f'Received status code {exception.status} '
        f'when calling get_turbinia_logs: {exception.body}')


@groups.logs_group.command('api')
@click.pass_context
@click.option(
    '--num_lines', '-n', help='Maximum number of log lines to retrieve.',
    required=False, is_flag=False, default=500)
def get_api_server_logs(ctx: click.Context, num_lines: int) -> None:
  """Gets Turbinia system logs."""
  client: api_client.ApiClient = ctx.obj.api_client
  api_instance = turbinia_logs_api.TurbiniaLogsApi(client)
  try:
    api_response = api_instance.get_api_server_logs(num_lines)
    click.echo(api_response)
  except exceptions.ApiException as exception:
    log.error(
        f'Received status code {exception.status} '
        f'when calling get_turbinia_logs: {exception.body}')
