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


@click.group('config')
def config_group():
  """Get Turbinia configuration."""


@click.group('status')
def status_group():
  """Get Turbinia request or task status."""


@click.group('result')
def result_group():
  """Get Turbinia request or task results."""


@click.group('jobs')
def jobs_group():
  """Get a list of enabled Turbinia jobs."""


@click.group('submit')
def submit_group():
  """Submit new requests to the Turbinia API server."""
