#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Script for deploying cloud functions."""

from __future__ import print_function

import subprocess
import sys

from turbinia import config

index_file = './index.yaml'

if len(sys.argv) > 1:
  function_names = [sys.argv[1]]
else:
  function_names = ['gettasks', 'closetasks']

config.LoadConfig()

for cloud_function in function_names:
  print('Deploying function {0:s}'.format(cloud_function))
  cmd = (
      'gcloud --project {0:s} functions deploy {1:s} --stage-bucket {2:s} '
      '--region {3:s} --runtime nodejs10 --trigger-http'.format(
          config.TURBINIA_PROJECT, cloud_function, config.BUCKET_NAME,
          config.TURBINIA_REGION))
  print(subprocess.check_call(cmd, shell=True))

print('/nCreating Datastore index from {0:s}'.format(index_file))
cmd = 'gcloud --quiet --project {0:s} datastore indexes create {1:s}'.format(
    config.TURBINIA_PROJECT, index_file)
subprocess.check_call(cmd, shell=True)
