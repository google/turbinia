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
"""Turbinia API client."""

import unittest

import turbinia_api_client
from turbinia_api_client.api.logs_api import LogsApi  # noqa: E501


class TestLogsApi(unittest.TestCase):
    """LogsApi unit test stubs"""

    def setUp(self):
        self.api = LogsApi()  # noqa: E501

    def tearDown(self):
        pass

    def test_get_logs_logs_query_get(self):
        """Test case for get_logs_logs_query_get

        Get Logs  # noqa: E501
        """
        pass


if __name__ == '__main__':
    unittest.main()
