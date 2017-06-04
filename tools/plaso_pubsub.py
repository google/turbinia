# Copyright 2016 Google Inc.
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

# HACK: We need the log2timeline tool and it only exists as a script.
# TODO(aarontp): Fix hack
import sys
sys.path.append('/usr/bin')

import argparse
import base64
import datetime
import httplib2
import os
import stat
import time

import requests
import BeautifulSoup
import json

# Google API
from googleapiclient import discovery
from googleapiclient import errors as google_errors
from googleapiclient import http as storage_http
from oauth2client import client as oauth2client

# Plaso
import plaso
import log2timeline

# Turbinia
from turbinia import config

_SLEEP_TIME_SEC = 1


def GetCurrentTimeUTC():
  return datetime.datetime.utcnow().strftime(u'%Y-%m-%dT%H:%M:%S+0000')


def IsBlockDevice(path):
  """Checks path to determine whether it is a block device.

  Args:
      path: String of path to check.

  Returns:
      Bool indicating success.
  """
  if not os.path.exists(path):
    return
  mode = os.stat(path).st_mode
  return stat.S_ISBLK(mode)


def WriteToStdOut(message):
  """Logging function to write to stdout.

  Args:
      message: String of message to write.
  """
  # TODO(aarontp): Convert to standard logging mechanism
  msg = u'{0:s} {1:s}\n'.format(GetCurrentTimeUTC(), message)
  sys.stdout.write(msg)
  sys.stdout.flush()


def WriteToStdErr(message):
  """Logging function to write to stderr.

  Args:
      message: String of message to write.
  """
  # TODO(aarontp): Convert to standard logging mechanism
  msg = u'{0:s} {1:s}\n'.format(GetCurrentTimeUTC(), message)
  sys.stderr.write(msg)
  sys.stderr.flush()


def CreateServiceClient(service):
  """Creates an API client for talking to Google Cloud.

  Args:
      service: String of service name.
  Returns:
      A client object for interacting with the cloud service.
  """
  WriteToStdOut(u'Create API client for service: {0:s}'.format(service))
  credentials = oauth2client.GoogleCredentials.get_application_default()
  http = httplib2.Http()
  credentials.authorize(http)
  return discovery.build(service, 'v1', http=http)


class TimesketchApiClient(object):
  """Client for interacting with Timesketch."""

  def __init__(self, server_ip, username, password):
    self.server_ip = server_ip
    self.host_url = u'https://{0:s}'.format(self.server_ip)
    self.session = self._CreateSession(username, password)

  def _CreateSession(self, username, password):
    """Creates an HTTP session to Timesketch.

    Args:
        username: String of username
        password: String of password

    Returns:
        Requests module HTTP session object
    """
    session = requests.Session()
    session.verify = False  # Depending on SSL cert is verifiable

    # Get the CSRF token from the response
    response = session.get(self.host_url)
    soup = BeautifulSoup.BeautifulSoup(response.text)
    csrf_token = soup.find(id='csrf_token').get('value')
    session.headers.update({
        'x-csrftoken': csrf_token,
        'referer': self.server_ip})

    # Do a POST to the login handler to set up the session cookies
    form_data = {u'username': username, u'password': password}
    session.post(u'{0:s}/login/'.format(self.host_url), data=form_data)
    return session

  def CreateSketch(self, name, description):
    """Creates a new Timesketch sketch.

    Args:
        name: Name of sketch to create.
        description: Description of sketch to create.

    Returns:
        Sketch Id
    """
    resource_url = u'{0:s}/api/v1/sketches/'.format(self.host_url)
    form_data = {u'name': name, u'description': description}
    response = self.session.post(resource_url, json=form_data)
    response_dict = response.json()
    sketch_id = response_dict[u'objects'][0]['id']
    return sketch_id

  def UploadTimeline(self, timeline_name, plaso_storage_path):
    """Uploads a plaso file to Timesketch to create a timeline.

    Args:
        timeline_name: Timeline name String.
        plaso_storage_path: Path String to plaso file to upload.

    Returns:
        Timeline Id
    """
    resource_url = u'{0:s}/api/v1/upload/'.format(self.host_url)
    files = {'file': open(plaso_storage_path, 'rb')}
    form_data = {u'name': timeline_name}
    response = self.session.post(resource_url, files=files, data=form_data)
    response_dict = response.json()
    index_id = response_dict[u'objects'][0]['id']
    return index_id

  def AddTimelineToSketch(self, sketch_id, index_id):
    """Links existing timeline to a sketch.

    Args:
        sketch_id: The Id of the sketch to link timline to.
        index_id: The Id of the timeline.

    Returns:
        The timeline Id.
    """
    resource_url = u'{0:s}/api/v1/sketches/{0:d}/'.format(
        self.host_url, sketch_id)
    form_data = {u'timelines': [index_id]}
    response = self.session.post(resource_url, json=form_data)
    response_dict = response.json()
    timeline_id = response_dict[u'objects'][0]['id']
    return timeline_id


class PlasoProcessor(object):
  """Handles Plaso processing of disk image.

  Attaches a disk to compute instance and runs Plaso processing on it. Also
  manages Timesketch sketch creation and timeline uploads with the Timesketch
  client.
  """

  def __init__(self):
    config.LoadConfig()

  def _WaitForOperation(self, client, operation):
    """Wait for a Cloud operation.

    Args:
      client: Google Cloud service client object.
      operation: Operation to run and wait for.
    Returns:
      Operation exection results.
    Raises:
      RuntimeError: If operation has an error.
    """
    WriteToStdOut(u'Waiting for operation to complete')
    while True:
      result = client.zoneOperations().get(
          project=config.PROJECT, zone=config.ZONE,
          operation=operation).execute()
      WriteToStdOut(u'Status: {0:s}'.format(result[u'status']))
      if result[u'status'] == u'DONE':
        if u'error' in result:
          WriteToStdErr(result)
          raise RuntimeError(result[u'error'][u'errors'][0][u'message'])
        return result
      time.sleep(_SLEEP_TIME_SEC)

  def _AttachDisk(self, client, disk):
    """Attaches a persistent disk to the machine.

    Args:
        client: Google Cloud service client object.
        disk: String of cloud path to disk
    """
    WriteToStdOut(u'Attaching disk')
    operation = client.instances().attachDisk(
        instance=config.INSTANCE,
        project=config.PROJECT,
        zone=config.ZONE,
        body={u'deviceName': config.DEVICE_NAME,
              u'source': disk}).execute()
    self._WaitForOperation(client, operation[u'name'])

  def _DetachDisk(self, client):
    """Detaches the disk from the machine.

    Args:
        client: Google Cloud service client object.
    """
    WriteToStdOut(u'Detaching disk')
    operation = client.instances().detachDisk(
        instance=config.INSTANCE,
        project=config.PROJECT,
        zone=config.ZONE,
        deviceName=config.DEVICE_NAME).execute()
    self._WaitForOperation(client, operation[u'name'])

  def _CopyFileToBucket(self, client, filename, object_name):
    """Copies file to Google Cloud storage bucket.

    Args:
        client: Google Cloud service client object.
        filename: String path to local file to copy.
        object_name: String name of file to copy.
    Returns:
        Boolean indicating success.
    """
    WriteToStdOut(u'Uploading file: {0:s}'.format(filename))
    media = storage_http.MediaFileUpload(
        filename, resumable=True, chunksize=1024000)
    request = client.objects().insert(
        bucket=config.BUCKET_NAME,
        name=object_name,
        media_body=media,
        body=filename)
    response = None
    while response is None:
      error_count = 0
      try:
        status, response = request.next_chunk()
      except (google_errors.HttpError, google_errors.ResumableUploadError) as e:
        if e.resp.status in [404]:
          return False
        elif e.resp.status in [500, 502, 503, 504]:
          time.sleep(5)
          # Call next_chunk() again, but use an exponential backoff for repeated
          # errors.
        elif e.resp.status in [400]:
          error_count += 1
          if error_count > 5:
            raise
          time.sleep(5)
        else:
          raise
    return True

  def Process(self, persistent_disk_name, project_name, disk_name):
    """Configure and run Plaso processing.

    Args:
        persistent_disk_name: Name of disk to process (created from snapshot).
        project_name: Project name of remote project being processed.
        disk_name: Name of remote disk that the snapshot was created from.
    """
    compute_client = CreateServiceClient(u'compute')
    path = u'/dev/disk/by-id/google-' + config.DEVICE_NAME

    if IsBlockDevice(path):
      WriteToStdOut(u'Disk already attached!')
      self._DetachDisk(compute_client)

    # Mount the disk
    disk_path = (
        u'projects/' + config.PROJECT + u'/zones/' + config.ZONE + u'/disks/' +
        persistent_disk_name)
    self._AttachDisk(compute_client, disk_path)
    output_file_basename = project_name + disk_name + GetCurrentTimeUTC()

    # Make sure we have a proper block device
    _RETRY_MAX = 10
    _RETRY_COUNT = 0
    while _RETRY_COUNT < _RETRY_MAX:
      if IsBlockDevice(path):
        WriteToStdOut(u'Block device: OK')
        break
      if os.path.exists(path):
        WriteToStdOut(
            u'Block device: Current mode is {0}'.format(os.stat(path).st_mode))
      _RETRY_COUNT += 1
      time.sleep(1)

    # Configure Log2Timeline
    tool = log2timeline.Log2TimelineTool()
    options = argparse.Namespace()
    options.debug = True
    options.hashers = u'all'
    options.dependencies_check = False
    options.serializer_format = u'json'
    options.status_view_mode = u'none'
    options.vss_stores = u'all'
    options.partition_number = u'all'
    options.log_file = os.path.join(
        config.SCRATCH_PATH, output_file_basename + u'.log')
    # Let plaso choose the appropriate number of workers
    options.workers = 0
    options.source = u'/dev/disk/by-id/google-' + config.DEVICE_NAME
    options.output = os.path.join(
        config.SCRATCH_PATH, output_file_basename + u'.plaso')
    tool.ParseOptions(options)
    WriteToStdOut(
        u'Plaso {0:s} {1:s} START'.format(plaso.GetVersion(), project_name))
    tool.ProcessSources()
    WriteToStdOut(
        u'Plaso {0:s} {1:s} END'.format(plaso.GetVersion(), project_name))

    # Add to timesketch
    timesketch_client = TimesketchApiClient(
        config.TIMESKETCH_HOST, config.TIMESKETCH_USER,
        config.TIMESKETCH_PASSWORD)
    # Create sketch
    sketch_id = timesketch_client.CreateSketch(
        name=sketch_name, description=sketch_name)
    # Create index from Plaso storage file
    index_id = timesketch_client.UploadTimeline(
        timeline_name=timeline_name, plaso_storage_path=storage_file)
    # Create sketch
    timesketch_client.AddTimelineToSketch(sketch_id, index_id)

    # Upload to GCS
    storage_client = CreateServiceClient(u'storage')
    self._CopyFileToBucket(
        storage_client, options.log_file, output_file_basename + u'.log')
    self._CopyFileToBucket(
        storage_client, options.output, output_file_basename + u'.plaso')
    self._DetachDisk(compute_client)


if __name__ == '__main__':
  config.LoadConfig()
  # Create PubSub client
  pubsub_client = CreateServiceClient(u'pubsub')
  subscription = u'projects/{0:s}/subscriptions/{1:s}'.format(
      config.PROJECT, config.PUBSUB_TOPIC)
  body = {
      u'returnImmediately': False,
      u'maxMessages': 1,}

  WriteToStdOut(u'Listen for messages')
  while True:
    resp = pubsub_client.projects().subscriptions().pull(
        subscription=subscription, body=body).execute()
    received_messages = resp.get(u'receivedMessages')
    if received_messages is not None:
      ack_ids = []
      pd_name = None
      disk_name = None
      project_name = None
      received_message = received_messages[0]
      pubsub_message = received_message.get(u'message')
      if pubsub_message:
        WriteToStdOut(u'PubSub message received')
        # Process messages
        data = base64.b64decode(str(pubsub_message.get(u'data')))
        try:
          data = json.loads(data)
          pd_name = data[u'pd_name']
          disk_name = data[u'disk_name']
          project_name = data[u'project_name']
          WriteToStdOut(u'Message body: {0:s}'.format(data))
        except (ValueError, KeyError) as e:
          WriteToStdErr(u'Error processing message: {0:s}'.format(e))

        # Get the message's ack ID
        ack_ids.append(received_message.get(u'ackId'))

        # Create a POST body for the acknowledge request
        ack_body = {u'ackIds': ack_ids}

        # Acknowledge the message.
        pubsub_client.projects().subscriptions().acknowledge(
            subscription=subscription, body=ack_body).execute()
        processor = PlasoProcessor()

        try:
          processor.Process(pd_name, project_name, disk_name)
        except RuntimeError as e:
          WriteToStdErr(u'Error: {0:s}'.format(e))
