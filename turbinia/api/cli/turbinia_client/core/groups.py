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

import click
import logging
import sys

from turbinia_api_lib import exceptions
from turbinia_client.factory import factory

log = logging.getLogger(__name__)


@click.group('config')
def config_group():
  """Get Turbinia configuration."""


@click.group('evidence')
def evidence_group():
  """Get or upload Turbinia evidence."""


@click.group('status')
def status_group():
  """Get Turbinia request or task status."""


@click.group('result')
def result_group():
  """Get Turbinia request or task results."""


@click.group('jobs')
def jobs_group():
  """Get a list of enabled Turbinia jobs."""


@click.group('report')
def report_group():
  """Get reports for Tasks or Requests."""


@click.group('logs')
def logs_group():
  """Get Turbinia logs."""


@click.group('submit')
@click.pass_context
def setup_submit(ctx: click.Context):
  try:
    ctx.obj.evidence_mapping = ctx.obj.get_evidence_arguments()
    ctx.obj.request_options = ctx.obj.get_request_options()
    # Build all the commands based on responses from the API server.
    request_commands = factory.CommandFactory.create_dynamic_objects(
        evidence_mapping=ctx.obj.evidence_mapping,
        request_options=ctx.obj.request_options)
    for command in request_commands:
      submit_group.add_command(command)
  except exceptions.ApiException as exception:
    log.error(
        'Error while attempting to contact the API server during setup: %s',
        exception)
    sys.exit(-1)


@click.group('submit', chain=True, invoke_without_command=True)
@click.pass_context
def submit_group(ctx: click.Context):
  """Submit new requests to the Turbinia API server.
  
  Please run this command without any arguments to view a list
  of available evidence types.
  """
  ctx.invoke(setup_submit)
  click.echo(submit_group.get_help(ctx))
