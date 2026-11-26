#!/usr/bin/env python3
#
# Generate daily metrics for Turbinia based on Redis data.

import argparse
import os
import re
import shutil
import subprocess
import sys

parser = argparse.ArgumentParser(
    description='Generate daily metrics for Turbinia based on Redis data.')
parser.add_argument(
    '-H', '--host', default='localhost',
    help='The hostname of the Redis server.')
parser.add_argument(
    '-p', '--port', default=6379, type=int,
    help='The port of the Redis server.')
parser.add_argument(
    '-o', '--output', default='turbinia_metrics.csv',
    help='The filename to output metrics into.')
args = parser.parse_args()

if os.path.exists(args.output):
  print(f'Filepath {args.output} already exists, exiting...')
  sys.exit(1)


rediscli = shutil.which('redis-cli')
if not rediscli:
  print('redis-cli not found... please install it and retry')
  sys.exit(1)

rediscli = f'{rediscli} -h {args.host} -p {args.port}'
# Map of day to metrics:
#  {'2024-09-20': {'task_count': 0, 'failed_tasks': 0, 'requests': 0}}
metrics = {}


# Get task data
task_data = subprocess.check_output(
    f'{rediscli} --scan --pattern "TurbiniaTask:*"', shell=True).decode('utf-8')
tasks = task_data.split()
print(f'Found {len(tasks)} tasks')
for task in tasks:
  start_time = subprocess.check_output(
    f'{rediscli} HGET {task} start_time', shell=True).decode('utf-8')
  start_time = start_time.replace('"', '').strip()
  match = re.match(r'^(.*)T', start_time)
  if not match:
    print(f'Invalid time found, skipping: {start_time}')
    continue
  start_time = match.group(1)
  success = subprocess.check_output(
    f'{rediscli} HGET {task} successful', shell=True).decode('utf-8')
  success = success.replace('"', '').strip()

  counts = metrics.get(start_time, {})
  if not counts:
    metrics[start_time] = {}
  metrics[start_time]['task_count'] = counts.get('task_count', 0) + 1
  failed = 1 if success != 'true' else 0
  metrics[start_time]['failed_tasks'] = counts.get('failed_tasks', 0) + failed


# Get request data
request_data = subprocess.check_output(
    f'{rediscli} --scan --pattern "TurbiniaRequest:*"',
    shell=True).decode('utf-8')
requests = request_data.split()
print(f'Found {len(requests)} requests')
for request in requests:
  start_time = subprocess.check_output(
    f'{rediscli} HGET {request} start_time', shell=True).decode('utf-8')
  start_time = start_time.replace('"', '').strip()
  match = re.match(r'^(.*)T', start_time)
  if not match:
    print(f'Invalid time found, skipping: {start_time}')
    continue
  start_time = match.group(1)

  counts = metrics.get(start_time, {})
  metrics[start_time]['requests'] = counts.get('requests', 0) + 1

# Write data to .csv
with open(args.output, 'wb') as fh:
  fh.write(
      'Date, Total Server Requests, Total Tasks, '
      'Total Failed Tasks\n'.encode('utf-8'))
  for start_time, data in sorted(metrics.items()):
    row = (
        f'{start_time}, {data.get("requests", 0)}, '
        f'{data.get("task_count", 0)}, {data.get("failed_tasks", 0)}\n')
    fh.write(row.encode('utf-8'))

print(f'Wrote {len(metrics)} entries to {args.output}')
