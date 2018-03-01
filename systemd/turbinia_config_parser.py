# -*- coding: utf-8 -*-
# # Copyright 2016 Google Inc.
# #
# # Licensed under the Apache License, Version 2.0 (the "License");
# # you may not use this file except in compliance with the License.
# # You may obtain a copy of the License at
# #
# #      http://www.apache.org/licenses/LICENSE-2.0
# #
# # Unless required by applicable law or agreed to in writing, software
# # distributed under the License is distributed on an "AS IS" BASIS,
# # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# # See the License for the specific language governing permissions and
# # limitations under the License.

from __future__ import unicode_literals
import imp
import itertools
import os
import sys

# This Turbinia config parser is written for init scripts using systemd,
# so this will not look for config files anywhere, except for /etc/turbinia.
# If there's a need to run Turbinia based on the config file in a homedir,
# you will need to run manually the start scripts.

# Look for config files with these names
CONFIGFILES = ['turbinia.conf', 'turbinia_config.py']
CONFIGPATH = ['/etc/turbinia']

def main():
  key = sys.argv[1]
  if key:
    config_file = None
    for _dir, _file in itertools.product(CONFIGPATH, CONFIGFILES):
      if os.path.exists(os.path.join(_dir, _file)):
        config_file = os.path.join(_dir, _file)
        break
    if config_file is None:
      exit(1)
    config = imp.load_source('config', config_file)
    import config
    try:
      print getattr(config, key.upper())
    except:
      exit(2)

if __name__ == '__main__':
  main()
