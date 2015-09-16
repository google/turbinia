# Copyright 2015 Google Inc.
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
"""Turbinia task."""

import json

from celery import Task


class TurbiniaTaskResult(object):
    """Object to store task results to be returned by a TurbiniaTask."""
    def __init__(
            self, results=None, version=None, metadata=None):
        """Initialize the TurbiniaTaskResult object.

        Args:
            results: List of task execution results.
            version: Version of the program being executed.
            metadata: Dictionary of metadata from the task.
        """

        self.results = results
        self.version = version
        self.metadata = metadata

        if not self.results:
            self.results = list()
        if not self.metadata:
            self.metadata = dict()

    def add_result(self, result_type, result):
        """Populate the results list.

        Args:
            result_type: Type of result, e.g. URL or filesystem path.
            result: Result string from the task.
        """
        self.results.append(dict(type=result_type, result=result))

    def to_json(self):
        """Convert object to JSON."""
        return json.dumps(self.__dict__)


class TurbiniaTask(Task):
    """Base class for Turbinia tasks."""
    abstract = True

    def __init__(self):
        super(TurbiniaTask, self).__init__()

    def run(self, *args, **kwargs):
        """Entry point the Celery worker uses to execute the task."""
        raise NotImplementedError
