# Copyright 2023 Google Inc.
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
"""Script to enumerate system pods.

This is to generate a list of containers that we can filter out by default in
the containr/docker enumeration tasks.
"""

import json
import subprocess
import sys

if len(sys.argv) < 3:
  print(
      f'usage: {sys.argv[0]} <project> <cluster to list> [<zone if other than us-central-f>]'
  )
  sys.exit(1)

project = sys.argv[1]
cluster = sys.argv[2]
if len(sys.argv) >= 4:
  zone = sys.argv[3]
else:
  zone = 'us-central1-f'
namespaces = {}

# Authenticate to cluster
auth_cmd = f'gcloud container clusters get-credentials {cluster} --zone {zone} --project {project}'
print(f'Authenticating to project {project} cluster {cluster} zone {zone}')
subprocess.check_call(auth_cmd.split(' '))

# Get pods data
cmd = f"kubectl get pods -o json -A"
pods_data = subprocess.check_output(cmd.split(' '))
pods_data = json.loads(pods_data)

filtered_data = []

for item in pods_data['items']:
  if not item.get('metadata'):
    continue

  name = item.get('metadata').get('name')
  namespace = item.get('metadata').get('namespace')

  if namespace not in namespaces:
    namespaces[namespace] = []

  for container in item['spec']['containers']:
    image = container["image"].split('@')[0]
    image = image.split(':')[0]
    namespaces[namespace].append(
        f'Pod Name: {name}, Container Name: {container["name"]} Image: {image}')

print()
for namespace, containers in namespaces.items():
  print(f'Namespace: {namespace}')
  for container_info in containers:
    print(f'\t{container_info}')