#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright 2018 Google Inc.
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
"""Graph to visualise job/evidence relationships."""

from __future__ import print_function
from __future__ import unicode_literals

import argparse
import graphviz
import sys

from turbinia.jobs import manager as jobs_manager

try:
  unicode
except NameError:
  unicode = str  # pylint: disable=redefined-builtin


def create_graph():
  """Create graph of relationships between Turbinia jobs and evidence.

  Returns:
    Instance of graphviz.dot.Digraph
  """
  dot = graphviz.Digraph(comment='Turbinia Evidence graph', format='png')
  for _, job in jobs_manager.JobsManager.GetJobs():
    dot.node(job.NAME)
    for evidence in job.evidence_input:
      dot.node(evidence.__name__, shape='box')
      dot.edge(evidence.__name__, job.NAME)

    for evidence in job.evidence_output:
      dot.node(evidence.__name__, shape='box')
      dot.edge(job.NAME, evidence.__name__)
  return dot


if __name__ == '__main__':
  parser = argparse.ArgumentParser(
      description='Create Turbinia evidence graph.')
  parser.add_argument(
      '-f', '--format', default='png',
      help='The format of the output file you wish to generate.  Specify '
      '"list" to list out the available output types.  More info is here: '
      'http://www.graphviz.org/doc/info/output.html')
  parser.add_argument(
      '-e', '--engine', default='dot',
      help='The graphviz engine used to generate the graph layout.  Specify '
      '"list" to list out the available engines.')
  parser.add_argument('filename', type=unicode, help='where to save the file')
  args = parser.parse_args()

  if args.format == 'list':
    formats = ' '.join(graphviz.FORMATS)
    print('Available format types: {0:s}'.format(formats))
    sys.exit(0)

  if args.format not in graphviz.FORMATS:
    print('Format type {0:s} is not supported'.format(args.format))
    sys.exit(1)

  if args.engine == 'list':
    engines = ' '.join(graphviz.ENGINES)
    print('Available graph layout engines: {0:s}'.format(engines))
    sys.exit(0)

  if args.engine not in graphviz.ENGINES:
    print('Layout engine type {0:s} is not supported'.format(args.engine))
    sys.exit(1)

  graph = create_graph()
  graph.engine = args.engine
  output_file = args.filename.replace('.png', '')

  try:
    rendered_graph = graph.render(
        filename=output_file, format=args.format, cleanup=True)
    print('Graph generated and saved to: {0}'.format(rendered_graph))
  except graphviz.ExecutableNotFound:
    print('Graphviz is not installed - Run: apt-get install graphviz')
