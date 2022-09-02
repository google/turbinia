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
"""Turbinia API server."""

from fastapi import APIRouter

from turbinia.api.routes import config
from turbinia.api.routes import jobs
from turbinia.api.routes import logs
from turbinia.api.routes import request
from turbinia.api.routes import result
from turbinia.api.routes import task

# Prefix API endpoints with /api/
router = APIRouter(prefix='/api')

# Register all API endpoints.
router.include_router(config.router)
router.include_router(jobs.router)
router.include_router(logs.router)
router.include_router(request.router)
router.include_router(result.router)
router.include_router(task.router)
