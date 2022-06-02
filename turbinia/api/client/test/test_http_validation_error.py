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


import sys
import unittest

import turbinia_api_client
from turbinia_api_client.model.validation_error import ValidationError
globals()['ValidationError'] = ValidationError
from turbinia_api_client.model.http_validation_error import HTTPValidationError


class TestHTTPValidationError(unittest.TestCase):
    """HTTPValidationError unit test stubs"""

    def setUp(self):
        pass

    def tearDown(self):
        pass

    def testHTTPValidationError(self):
        """Test HTTPValidationError"""
        # FIXME: construct object with mandatory attributes with example values
        # model = HTTPValidationError()  # noqa: E501
        pass


if __name__ == '__main__':
    unittest.main()
