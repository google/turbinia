/*
Copyright 2022 Google Inc. All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import axios from 'axios'

const RestApiClient = axios.create()

// Show message on errors.
RestApiClient.interceptors.response.use(
  function (response) {
    return response
  },
  function (error) {
    console.error(error.response.data)
    return Promise.reject(error)
  }
)

export default {
  // Request List
  getRequestList() {
    return RestApiClient.get('/api/request/summary')
  },

  // Request Output
  getRequestOutput(request_id) {
    return RestApiClient.get('/api/result/request/' + request_id, { responseType: 'blob' })
  },

  // Task List
  getTaskList(request_id) {
    return RestApiClient.get('/api/request/' + request_id)
  },

  // Task Details
  getTaskDetails(task_id) {
    return RestApiClient.get('/api/task/' + task_id)
  },

  // Task Output
  getTaskOutput(task_id) {
    return RestApiClient.get('/api/result/task/' + task_id, { responseType: 'blob' })
  },
}
