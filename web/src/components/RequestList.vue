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
        <template v-slot:[`item.status`]="{ item }">
          <div v-if="item.status === 'successful'">
            <v-tooltip right>
              Completed successfully
              <template v-slot:activator="{ on, attrs }">
                <v-icon v-on="on" v-bind="attrs" color="green"> mdi-check </v-icon>
              </template>
            </v-tooltip>
          </div>
          <div v-else-if="item.status === 'completed_with_errors'">
            <v-tooltip right>
              Completed with Task failures
              <template v-slot:activator="{ on, attrs }">
                <v-icon v-on="on" v-bind="attrs" color="orange"> mdi-alert </v-icon>
              </template>
            </v-tooltip>
          </div>
          <div v-else-if="item.status === 'failed'">
            <v-tooltip right>
              <template v-slot:activator="{ on, attrs }">
                <v-icon v-on="on" v-bind="attrs" color="red"> mdi-alert-circle </v-icon>
              </template>
            </v-tooltip>
          </div>
          <div v-else>
            <v-tooltip right>
              {{ item.total_tasks - item.successful_tasks - item.failed_tasks }} Tasks remaining
              <template v-slot:activator="{ on, attrs }">
                <v-progress-circular v-on="on" v-bind="attrs" :value="item.outstanding_perc" color="blue">
                  {{ item.outstanding_perc }}
                </v-progress-circular>
              </template>
            </v-tooltip>
          </div>
        </template>
        <template v-slot:expanded-item="{ headers, item }">
          <td :colspan="headers.length">
            <task-list :request-id="item.request_id" :key="item.request_id"> </task-list>
          </td>
        </template>
        <template v-slot:[`item.request_results`]="{ item }">
          <v-tooltip right>
            Download Request output
            <template v-slot:activator="{ on, attrs }">
              <v-btn icon v-on="on" v-bind="attrs" @click="getRequestOutput(item.request_id)">
                <v-icon> mdi-folder-arrow-down-outline </v-icon>
              </v-btn>
            </template>
          </v-tooltip>
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
        { text: 'Results', value: 'request_results' },
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
            let outstanding_perc = Math.round(
              ((data[req].failed_tasks + data[req].successful_tasks) / data[req].task_count) * 100
            )
            requestSummary.push({
              request_id_reason: data[req].request_id + ' - ' + data[req].reason,
              request_id: data[req].request_id,
              last_task_update_time: data[req].last_task_update_time,
              requester: data[req].requester,
              total_tasks: data[req].task_count,
              running_tasks: data[req].running_tasks,
              successful_tasks: data[req].successful_tasks,
              failed_tasks: data[req].failed_tasks,
              outstanding_perc: outstanding_perc,
              status: data[req].status,
            })
          }
          this.requestSummary = requestSummary
        })
        .catch((e) => {
          console.error(e)
        })
    },
    getRequestOutput: function (request_id) {
      ApiClient.getRequestOutput(request_id)
        .then(({ data }) => {
          const downloadObj = window.URL.createObjectURL(new Blob([data]))
          const link = document.createElement('a')
          link.href = downloadObj
          link.setAttribute('download', request_id + '.zip')
          document.body.appendChild(link)
          link.click()
          link.remove()
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
