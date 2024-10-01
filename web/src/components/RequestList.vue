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
    <template>
      <div class="text-center pa-4">
        <v-dialog v-model="openDialog" width="auto">
          <v-card max-width="400" prepend-icon="mdi-filter-menu"
            text="You may filter by Job Name either including or excluding Jobs." title="Filter by Job Name">
            <v-form @submit.prevent>
              <v-radio-group v-model="radioFilter">
                <v-radio label="Including Jobs" :value="true"></v-radio>
                <v-radio label="Excluding Jobs" :value="false"></v-radio>
              </v-radio-group>
              <v-select clearable chips label="Select" :items="this.availableJobs" v-model="filterJobs"
                multiple></v-select>
            </v-form>
            <template v-slot:actions>
              <v-btn type="submit" @click="filterSelectedJobs" class="ms-auto" text="Submit"></v-btn>
              <v-btn type="close" text="Close" @click="openDialog = false"></v-btn>
            </template>
          </v-card>
        </v-dialog>
      </div>
    </template>
    <v-card title="Request List">
      <template v-slot:append>
        <v-tooltip right>
          <template v-slot:activator="{ props }">
            <v-btn icon="mdi-refresh" color="blue lighten-2" @click="getRequestList()" v-bind="props"
              class="justify-left">
            </v-btn>
          </template>
          Refresh Request List
        </v-tooltip>
      </template>
      <v-spacer></v-spacer>
      <v-text-field v-model="search" append-icon="mdi-magnify" label="Search" single-line hide-details>
        <template v-slot:append>
          <v-chip-group v-model="filterChips" column multiple>
            <v-tooltip location="top">
              <template v-slot:activator="{ props }">
                <v-chip v-bind="props" text="Running" filter @click="this.filterRunning = !this.filterRunning">
                </v-chip>
              </template>
              Filter by running or pending Tasks
            </v-tooltip>
            <v-tooltip location="top">
              <template v-slot:activator="{ props }">
                <v-chip v-bind="props" text="Successful" filter @click="this.filterSuccess = !this.filterSuccess">
                </v-chip>
              </template>
              Filter by successful Tasks
            </v-tooltip>
            <v-tooltip location="top">
              <template v-slot:activator="{ props }">
                <v-chip v-bind="props" text="Failed" filter @click="this.filterFailed = !this.filterFailed">
                </v-chip>
              </template>
              Filter by failed Tasks
            </v-tooltip>
          </v-chip-group>
          <v-tooltip location="right">
            <template v-slot:activator="{ props }">
              <v-btn v-bind="props" variant="text" icon="mdi-filter" @click="openDialog = true"
                selected-class="activated" :class="{ activated: jobFilterActive == true }">
              </v-btn>
            </template>
            Filter by Job Name
          </v-tooltip>
        </template>
      </v-text-field>
      <v-spacer></v-spacer>
      <v-data-table :headers="headers" :items="requestSummary" :search="search" density="compact"
        item-value="request_id" :footer-props="{ itemsPerPageOptions: [10, 20, 40, -1] }" :loading="isLoading"
        :sort-by="sortBy" multi-sort show-expand hover>
        <template v-slot:[`item.request_id`]="{ item }">
          <v-btn variant="text" :ripple="true" :key="item.request_id"
            @click="getRequestDetails(item.request_id) + selectActiveRow(item.request_id)" selected-class="activated"
            :class="{ activated: isActiveRow == item.request_id }">
            {{ item.request_id }}
          </v-btn>
        </template>
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
              <task-list :request-id="item.request_id"
                :key="this.filterJobs + this.filterRunning + this.filterFailed + this.filterSuccess"
                :filterRunning="this.filterRunning" :filterFailed="this.filterFailed"
                :filterSuccess="this.filterSuccess" :filterJobs="this.filterJobs" :radioFilter="this.radioFilter"
                :isActiveRow="this.isActiveRow">
              </task-list>
            </td>
          </tr>
        </template>
      </v-data-table>
    </v-card>
  </section>
</template>

<script>
import ApiClient from '../utils/RestApiClient.js'
import TaskList from './TaskList.vue'
import { mergeProps } from 'vue'
import { truncate } from '../App.vue'

export default {
  components: { TaskList },
  inject: ['getRequestDetails'],
  provide() {
    return {
      selectActiveRow: this.selectActiveRow,
    }
  },
  data() {
    return {
      search: '',
      isLoading: false,
      headers: [
        { title: '', key: 'data-table-expand', width: '1%' },
        { title: 'Request', key: 'request_id', width: '15%' },
        { title: 'Last Task Update Time', key: 'last_task_update_time', width: '20%' },
        { title: 'Evidence Name', key: 'evidence_name', width: '25%' },
        { title: 'Requester', key: 'requester', width: '12%' },
        { title: 'Reason', key: 'request_id_reason', width: '10%' },
        { title: 'Status', key: 'status', width: '10%' },
      ],
      requestSummary: [],
      sortBy: [{ key: 'last_task_update_time', order: 'desc' }],
      availableJobs: [],
      filterChips: [],
      filterJobs: [],
      jobFilterActive: false,
      filterRunning: false,
      filterFailed: false,
      filterSuccess: false,
      openDialog: false,
      radioFilter: true,
      isActiveRow: null,
    }
  },
  methods: {
    mergeProps,
    getRequestList: function () {
      ApiClient.getRequestList()
        .then((response) => {
          this.isLoading = true
          let requestSummary = []
          let data = response.data['requests_status']
          for (const req in data) {
            let outstanding_perc = Math.floor(
              ((data[req].failed_tasks + data[req].successful_tasks) / data[req].task_count) * 100
            )
            let reason = null
            if (data[req].reason) {
              reason = data[req].reason
            } else {
              reason = 'N/A'
            }
            requestSummary.push({
              request_id_reason: reason,
              request_id: data[req].request_id,
              last_task_update_time: data[req].last_task_update_time,
              requester: data[req].requester,
              total_tasks: data[req].task_count,
              running_tasks: data[req].running_tasks,
              successful_tasks: data[req].successful_tasks,
              failed_tasks: data[req].failed_tasks,
              outstanding_perc: outstanding_perc,
              status: data[req].status,
              evidence_name: truncate(data[req].evidence_name, 64, '...'),
              evidence_id: data[req].evidence_id,
            })
          }
          this.isLoading = false
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
    getAvailableJobs: function () {
      ApiClient.getAvailableJobs()
        .then((response) => {
          let available = response.data
          this.availableJobs = available.sort()
        })
        .catch((e) => {
          console.error(e)
        })
    },
    filterSelectedJobs: function () {
      if (this.filterJobs.length > 0) {
        this.jobFilterActive = true
      } else {
        this.jobFilterActive = false
      }
      this.openDialog = false
    },
    selectActiveRow: function (id) {
      // Accepts Request ID or Task ID
      this.isActiveRow = id
    }
  },
  mounted() {
    this.getRequestList()
    this.getAvailableJobs()
  },
}
</script>

<style scoped>
.activated {
  background-color: rgba(128, 128, 128, 0.4);
}
</style>