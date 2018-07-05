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
"""Graph to visualise job/evidence dependencies."""

from __future__ import unicode_literals

import argparse
import graphviz

from turbinia.jobs import get_jobs as turbinia_jobs


def create_graph():
  dot = graphviz.Digraph(comment='Turbinia Evidence graph', format='png')
  for job in turbinia_jobs():
    dot.node(job.name)
    for evidence in job.evidence_input:
      dot.node(evidence.__name__, shape='box')
      dot.edge(evidence.__name__, job.name)

    for evidence in job.evidence_output:
      dot.node(evidence.__name__, shape='box')
      dot.edge(job.name, evidence.__name__)
  return dot


parser = argparse.ArgumentParser(description='Create Turbinia evidence graph.')
parser.add_argument('filename', type=unicode, help='where to save the file')
args = parser.parse_args()

graph = create_graph()

print args.filename

try:
  rendered_graph = graph.render(filename='/tmp/turbinia', cleanup=True)
  print(rendered_graph)
except graphviz.ExecutableNotFound:
  print('Graphviz is not installed - Run: apt-get install graphviz')

