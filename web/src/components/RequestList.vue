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
        <v-text-field v-model="search" append-icon="mdi-magnify" label="Search" single-line hide-details>
          <template v-slot:append>
            <v-tooltip right>
              <template v-slot:activator="{ props }">
                <v-btn icon="mdi-refresh" color="blue lighten-2" @click="getRequestList()" v-bind="props"
                  location="bottom">
                </v-btn>
              </template>
              Refresh Request List
            </v-tooltip>
          </template>
        </v-text-field>
        <v-spacer></v-spacer>
      </v-card-title>
      <v-data-table :headers="headers" :items="requestSummary" :search="search"
        :footer-props="{ itemsPerPageOptions: [10, 20, 40, -1] }" multi-sort item-value="request_id_reason" show-expand
        hover>
        <template v-slot:[`item.status`]="{ item }">
          <div v-if="item.status === 'successful'">
            <v-tooltip text="Completed successfully">
              <template v-slot:activator="{ props }">
                <v-icon v-bind="props" color="green" icon="mdi-check"></v-icon>
              </template>
            </v-tooltip>
          </div>
          <div v-else-if="item.status === 'completed_with_errors'">
            <v-tooltip text="Completed with Task failures">
              <template v-slot:activator="{ props }">
                <v-icon v-bind="props" color="orange" icon="mdi-alert"></v-icon>
              </template>
            </v-tooltip>
          </div>
          <div v-else-if="item.status === 'failed'">
            <v-tooltip text="Failed">
              <template v-slot:activator="{ props }">
                <v-icon v-bind="props" color="red" icon="mdi-alert-circle"></v-icon>
              </template>
            </v-tooltip>
          </div>
          <div v-else>
            <v-tooltip>
              {{ item.total_tasks - item.successful_tasks - item.failed_tasks }} Tasks remaining
              <template v-slot:activator="{ props }">
                <v-progress-circular v-bind="props" :value="item.outstanding_perc" color="blue">
                  {{ item.outstanding_perc }}
                </v-progress-circular>
              </template>
            </v-tooltip>
          </div>
        </template>
        <template v-slot:expanded-row="{ columns, item }">
          <tr>
            <td :colspan="columns.length">
              <task-list :request-id="item.request_id" :key="item.request_id"> </task-list>
            </td>
          </tr>
        </template>
        <template v-slot:[`item.request_results`]="{ item }">
          <v-snackbar timeout="5000" color="primary" location="top" height="55">
            Request output is <strong>downloading in the background</strong>, please wait
            <v-progress-circular color="white" indeterminate></v-progress-circular>
            <template v-slot:activator="{ props: snackbar }">
              <v-tooltip top text="Download request output">
                <template v-slot:activator="{ props: tooltip }">
                  <v-btn icon="mdi-folder-arrow-down-outline" variant="text" v-bind="mergeProps(snackbar, tooltip)"
                    @click="getRequestOutput(item.request_id)">
                  </v-btn>
                </template>
              </v-tooltip>
            </template>
          </v-snackbar>
        </template>
      </v-data-table>
    </v-card>
  </section>
</template>

<script>
import ApiClient from '../utils/RestApiClient.js'
import TaskList from './TaskList.vue'
import { mergeProps } from 'vue'

export default {
  components: { TaskList },
  data() {
    return {
      search: '',
      headers: [
        { title: 'Request', key: 'request_id_reason' },
        { title: 'Last Task Update Time', key: 'last_task_update_time' },
        { title: 'Evidence Name', key: 'evidence_name' },
        { title: 'Requester', key: 'requester' },
        { title: 'Total Tasks', key: 'total_tasks' },
        { title: 'Running Tasks', key: 'running_tasks' },
        { title: 'Successful Tasks', key: 'successful_tasks' },
        { title: 'Failed Tasks', key: 'failed_tasks' },
        { title: 'Status', key: 'status' },
        { title: 'Results', key: 'request_results' },
      ],
      requestSummary: [],
    }
  },
  methods: {
    mergeProps,
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
              evidence_name: data[req].evidence_name,
              evidence_id: data[req].evidence_id,
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
          link.setAttribute('download', request_id + '.tgz')
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
