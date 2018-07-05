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

