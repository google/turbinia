<!--
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
-->

<template>
  <section>
    <v-card>
      <v-card-title>
        Request List
        <v-spacer></v-spacer>
        <v-text-field v-model="search" append-icon="mdi-magnify" label="Search" single-line hide-details></v-text-field>
        <v-spacer></v-spacer>
        <v-tooltip left>
          <template v-slot:activator="{ on, attrs }">
            <v-btn fab color="blue lighten-2" @click="getRequestList()" v-bind="attrs" v-on="on">
              <v-icon>mdi-refresh</v-icon>
            </v-btn>
          </template>
          Refresh Request List
        </v-tooltip>
      </v-card-title>
      <v-data-table
        :headers="headers"
        :items="requestSummary"
        :search="search"
        :footer-props="{ itemsPerPageOptions: [10, 20, 40, -1] }"
        multi-sort
        item-key="request_id_reason"
        show-expand
        single-expand
      >
        <template v-slot:expanded-item="{ headers, item }">
          <task-list :request-headers="headers" :request-id="item.request_id"> </task-list>
        </template>
      </v-data-table>
    </v-card>
  </section>
</template>

<script>
import ApiClient from '../utils/RestApiClient.js'
import TaskList from './TaskList'

export default {
  components: { TaskList },
  data() {
    return {
      search: '',
      headers: [
        { text: 'Request', value: 'request_id_reason' },
        { text: 'Last Task Update Time', value: 'last_task_update_time' },
        { text: 'Requester', value: 'requester' },
        { text: 'Total Tasks', value: 'total_tasks' },
        { text: 'Running Tasks', value: 'running_tasks' },
        { text: 'Successful Tasks', value: 'successful_tasks' },
        { text: 'Failed Tasks', value: 'failed_tasks' },
        { text: 'Status', value: 'status' },
      ],
      requestSummary: [],
    }
  },
  methods: {
    getRequestList: function () {
      ApiClient.getRequestList()
        .then((response) => {
          let requestSummary = []
          let data = response.data['requests_status']
          for (const req in data) {
            requestSummary.push({
              request_id_reason: data[req].request_id + ' - ' + data[req].reason,
              request_id: data[req].request_id,
              last_task_update_time: data[req].last_task_update_time,
              requester: data[req].requester,
              total_tasks: data[req].task_count,
              running_tasks: data[req].running_tasks,
              successful_tasks: data[req].successful_tasks,
              failed_tasks: data[req].failed_tasks,
              status: data[req].status,
            })
          }
          this.requestSummary = requestSummary
        })
        .catch((e) => {
          console.error(e)
        })
    },
  },
  mounted() {
    this.getRequestList()
  },
}
</script>
