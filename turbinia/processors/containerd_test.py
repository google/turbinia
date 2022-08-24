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
"""Tests for PreprocessMountContainerdFS."""

import os
import unittest

from turbinia.processors import containerd


class MountContainerdFSTest(unittest.TestCase):
  """Tests for mounting containerd filesystem."""

  def testPreprocessMountContainerdFS(self):
    """Test PreprocessMountContainerdFS function."""
    image_path = '/mnt/mock'
    namespace = 'default'
    container_id = 'nginx01'

    # Only run if test image is loaded.
    if not os.path.exists(image_path):
      print(f'Disk image mount path {image_path} does not exist')
      return

    containerd_mount_path = containerd.PreprocessMountContainerdFS(
        image_path, namespace, container_id)
    print(containerd_mount_path)


if __name__ == '__main__':
  unittest.main()
