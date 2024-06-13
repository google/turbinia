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
"""Task for analyzing containerd containers."""

import json
import logging
import subprocess
import tempfile

from turbinia import config
from turbinia import TurbiniaException
from turbinia.evidence import ContainerdContainer
from turbinia.evidence import EvidenceState as state
from turbinia.workers import Priority
from turbinia.workers import TurbiniaTask

log = logging.getLogger(__name__)

CE_BINARY = '/opt/container-explorer/bin/ce'
CE_SUPPORT_FILE = '/opt/container-explorer/etc/supportcontainer.yaml'
POD_NAME_LABEL = 'io.kubernetes.pod.name'


class ContainerdEnumerationTask(TurbiniaTask):
  """Enumerate containerd containers on Linux."""

  REQUIRED_STATES = [state.ATTACHED, state.MOUNTED]

  TASK_CONFIG = {
      # These filters will all match on partial matches, e.g. an image filter of
      # ['gke.gcr.io/'] will filter out image `gke.gcr.io/event-exporter`.
      #
      # Which k8 namespaces to filter out by default
      'filter_namespaces': ['kube-system'],
      'filter_pod_names': ['sidecar', 'k8s-sidecar', 'konnectivity-agent'],
      # Taken from
      # https://github.com/google/container-explorer/blob/main/supportcontainer.yaml
      'filter_images': [
          'gcr.io/gke-release-staging/cluster-proportional-autoscaler-amd64',
          'gcr.io/k8s-ingress-image-push/ingress-gce-404-server-with-metrics',
          'gke.gcr.io/ingress-gce-404-server-with-metrics',
          'gke.gcr.io/cluster-proportional-autoscaler',
          'gke.gcr.io/csi-node-driver-registrar',
          'gke.gcr.io/event-exporter',
          'gke.gcr.io/fluent-bit',
          'gke.gcr.io/fluent-bit-gke-exporter',
          'gke.gcr.io/gcp-compute-persistent-disk-csi-driver',
          'gke.gcr.io/gke-metrics-agent',
          'gke.gcr.io/k8s-dns-dnsmasq-nanny',
          'gke.gcr.io/k8s-dns-kube-dns',
          'gke.gcr.io/k8s-dns-sidecar',
          'gke.gcr.io/kube-proxy-amd64',
          'gke.gcr.io/prometheus-to-sd',
          'gke.gcr.io/proxy-agent',
          'k8s.gcr.io/metrics-server/metrics-server',
          'gke.gcr.io/metrics-server',
          'k8s.gcr.io/pause',
          'gke.gcr.io/pause',
          'gcr.io/gke-release-staging/addon-resizer',
          'gcr.io/gke-release-staging/cpvpa-amd64',
          'gcr.io/google-containers/pause-amd64',
          'gke.gcr.io/addon-resizer',
          'gke.gcr.io/cpvpa-amd64',
          'k8s.gcr.io/kube-proxy-amd64',
          'k8s.gcr.io/prometheus-to-sd',
      ],
  }

  def list_containers(self, evidence, _, detailed_output=False):
    """List containerd containers in the evidence.

    Args:
      evidence (Evidence): Input evidence to be processed.
      detailed_output (bool): Check if detailed output is required.

    Returns:
      list(dict): Containers information
    """
    config.LoadConfig()
    containers = None
    image_path = evidence.mount_path

    outputfile = tempfile.mkstemp()[1]
    list_cmd = [
        'sudo', CE_BINARY, '--support-container-data', CE_SUPPORT_FILE,
        '--output', 'json', '--output-file', outputfile, '--image-root',
        image_path, 'list', 'containers'
    ]
    log.info(f'Running {list_cmd}')

    try:
      #json_data = subprocess.check_output(list_cmd).decode('utf-8')
      subprocess.check_call(list_cmd)
      with open(outputfile, 'r') as fh:
        json_data = fh.read()
        if json_data:
          containers = json.loads(json_data)
    except json.JSONDecodeError as e:
      raise TurbiniaException(
          f'Error decoding container-explorer output: {e}') from e
    except subprocess.CalledProcessError as e:
      raise TurbiniaException(f'container-explorer return error: {e}') from e
    except FileNotFoundError as e:
      raise TurbiniaException(f'output file {outputfile} does not exist') from e

    return self._list_containers_result(containers, detailed_output)

  def _list_containers_result(self, containers, detailed_output):
    """ Determine and return containers information.

    Args:
      containers (list(dict)): Containers information
      detailed_output (bool): Check if detailed output is required.

    Returns:
      list(dict): List containers basic or complete output.
    """
    if not containers:
      return containers

    if detailed_output:
      return containers

    basic_fields = [
        'Name', 'Namespace', 'Image', 'ContainerType', 'ID', 'Hostname',
        'CreatedAt', 'Labels'
    ]
    basic_containers = []

    for container in containers:
      basic_container = {}
      for key, value in container.items():
        if key not in basic_fields:
          continue
        basic_container[key] = value
      basic_containers.append(basic_container)

    return basic_containers

  def run(self, evidence, result):
    """Run ContainerdEnumerationTask.

    Args:
      evidence (Evidence): Evidence to process.
      result (TurbiniaTaskResult): The object to place task result.

    Returns:
      TurbiniaTaskResult object
    """
    summary = ''
    success = False
    report_data = []
    filter_namespaces = self.task_config.get('filter_namespaces')
    filter_pod_names = self.task_config.get('filter_pod_names')
    filter_images = self.task_config.get('filter_images')
    filtered_container_list = []

    image_path = evidence.mount_path
    if not image_path:
      summary = (
          f'Evidence {evidence.name}:{evidence.source_path} is not '
          'mounted')
      result.close(self, success=False, status=summary)
      return result

    try:
      # 1. List containers
      containers = self.list_containers(evidence, result)
      if not containers:
        result.close(self, success=True, status='Found 0 containers')
        return result

      container_ids = [x.get('ID') for x in containers]
      report_data.append(
          f'Found {len(container_ids)} containers: {", ".join(container_ids)}')

      # 2. Add containers as evidences
      new_evidence = []
      for container in containers:
        namespace = container.get('Namespace', 'UnknownNamespace')
        container_id = container.get('ID', 'UnknownContainerID')
        if container.get('Labels'):
          pod_name = container.get('Labels').get(
              POD_NAME_LABEL, 'UnknownPodName')
        else:
          pod_name = 'UnknownPodName'
        container_type = container.get('ContainerType') or None
        image = container.get('Image')
        if image:
          image_short = image.split('@')[0]
          image_short = image_short.split(':')[0]
        else:
          image_short = 'UnknownImageName'

        if not namespace or not container_id:
          message = (
              f'Skipping container with empty value namespace ({namespace})'
              f' or container_id ({container_id})')
          result.log(message)
          report_data.append(message)
          continue

        # Filter out configured namespaces/containers/images.  Even though we
        # could let container explorer filter these before we get them we want
        # to do it here so that we can report on what was available and filtered
        # out to give the analyst the option to reprocess these containers.
        if filter_namespaces:
          if namespace in filter_namespaces:
            message = (
                f'Filtering out container {container_id} because namespace '
                f'matches filter.')
            result.log(message)
            report_data.append(message)
            filtered_container_list.append(container_id)
            continue
        if filter_images:
          if image_short in filter_images:
            message = (
                f'Filtering out image {image} because image matches filter')
            result.log(message)
            report_data.append(message)
            filtered_container_list.append(container_id)
            continue
        if filter_pod_names:
          if pod_name in filter_pod_names:
            message = (
                f'Filtering out container {container_id} because container '
                f'name matches filter')
            result.log(message)
            report_data.append(message)
            filtered_container_list.append(container_id)
            continue

        # We want to process docker managed container using Docker-Explorer
        if container_type and container_type.lower() == 'docker':
          result.log(
              f'Skipping docker managed container {namespace}:{container_id}')
          report_data.append(
              f'Skipping docker managed container {namespace}:{container_id}')
          continue

        container_evidence = ContainerdContainer(
            namespace=namespace, container_id=container_id,
            image_name=image_short, pod_name=pod_name)
        new_evidence.append(container_evidence.name)

        result.add_evidence(container_evidence, evidence.config)
        result.log(
            f'Adding container evidence {container_evidence.name} '
            f'type {container_type}')

      summary = (
          f'Found {len(container_ids)} containers, added {len(new_evidence)} '
          f'(filtered out {len(filtered_container_list)})')
      success = True
      if filtered_container_list:
        report_data.append(
            f'Filtered out {len(filtered_container_list)} containers: '
            f'{", ".join(filtered_container_list)}')
        report_data.append(
            f'Container filter lists: Namespaces: {filter_namespaces}, Images: {filter_images}, '
            f'Pod Names: {filter_pod_names}')
        report_data.append(
            'To process filtered containers, adjust the ContainerEnumeration '
            'Task config filter* parameters with a recipe')
    except TurbiniaException as e:
      summary = f'Error enumerating containerd containers: {e}'
      report_data.append(summary)

    # 3. Prepare result
    result.report_priority = Priority.LOW
    result.report_data = '\n'.join(report_data)
    result.close(self, success=success, status=summary)
    return result
