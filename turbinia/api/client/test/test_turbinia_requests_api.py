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
from turbinia_api_client.api.turbinia_requests_api import TurbiniaRequestsApi  # noqa: E501


class TestTurbiniaRequestsApi(unittest.TestCase):
    """TurbiniaRequestsApi unit test stubs"""

    def setUp(self):
        self.api = TurbiniaRequestsApi()  # noqa: E501

    def tearDown(self):
        pass

    def test_create_request_request_post(self):
        """Test case for create_request_request_post

        Create Request  # noqa: E501
        """
        pass

    def test_get_request_status_request_request_id_get(self):
        """Test case for get_request_status_request_request_id_get

        Get Request Status  # noqa: E501
        """
        pass

    def test_get_requests_summary_request_summary_get(self):
        """Test case for get_requests_summary_request_summary_get

        Get Requests Summary  # noqa: E501
        """
        pass


if __name__ == '__main__':
    unittest.main()
