<!--
Copyright 2024 Google Inc. All rights reserved.
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
  <div>
    <v-card-title>
      Request Details
      <v-snackbar timeout="5000" color="primary" location="top" height="55">
        Request output is <strong>downloading in the background</strong>, please wait
        <v-progress-circular color="white" indeterminate></v-progress-circular>
        <template v-slot:activator="{ props: snackbar }">
          <v-tooltip location="top" text="Download request output">
            <template v-slot:activator="{ props: tooltip }">
              <v-btn icon="mdi-folder-arrow-down-outline" variant="text" v-bind="mergeProps(snackbar, tooltip)"
                @click="getRequestOutput(requestDetails.request_id)">
              </v-btn>
            </template>
          </v-tooltip>
        </template>
      </v-snackbar>
      <v-tooltip location="top" text="View request report">
        <template v-slot:activator="{ props: tooltip }">
          <v-btn icon="mdi-file-document-outline" variant="text" v-bind="tooltip"
            @click="getMarkdownReport(requestDetails.request_id)">
          </v-btn>
        </template>
      </v-tooltip>
    </v-card-title>
    <v-alert v-if="requestDetails.status === 'successful'" type="success" prominent>
      Request <strong>{{ requestDetails.request_id }}</strong> completed successfully.
    </v-alert>
    <v-alert v-else-if="requestDetails.status === 'running'" type="info" prominent>
      Request <strong>{{ requestDetails.request_id }}</strong> has <strong>{{ requestDetails.task_count -
          requestDetails.successful_tasks - requestDetails.failed_tasks }}</strong> Tasks remaining.
    </v-alert>
    <v-alert v-else-if="requestDetails.status === 'completed_with_errors'" type="warning" prominent>
      Request <strong>{{ requestDetails.request_id }}</strong> completed with <strong>{{ requestDetails.failed_tasks
        }}</strong> failed Tasks.
    </v-alert>
    <v-alert v-else type="error" prominent>
      Request <strong>{{ requestDetails.request_id }}</strong> was not successful.
    </v-alert>
    <v-card>
      <v-list density="compact" v-model:opened="openGroups">
        <v-list-group value="ids">
          <template v-slot:activator="{ props }">
            <v-list-item v-bind="props" title="Associated IDs"></v-list-item>
          </template>
          <v-list-item title="Request ID:">
            {{ requestDetails.request_id }}
          </v-list-item>
          <v-list-item title="Evidence ID:">
            {{ requestDetails.evidence_id }}
          </v-list-item>
          <v-list-item title="Reason:">
            {{ requestDetails.reason }}
          </v-list-item>
        </v-list-group>
        <v-list-group value="details">
          <template v-slot:activator="{ props }">
            <v-list-item v-bind="props" title="Processing Details"></v-list-item>
          </template>
          <v-list-item title="Evidence Name:">
            {{ requestDetails.evidence_name }}
          </v-list-item>
          <v-list-item title="Last Update:">
            {{ requestDetails.last_task_update_time }}
          </v-list-item>
          <v-list-item title="Requester:">
            {{ requestDetails.requester }}
          </v-list-item>
          <v-list-item title="Status:">
            {{ requestDetails.status }}
          </v-list-item>
          <v-list-item title="Total:">
            {{ requestDetails.task_count }} Tasks
          </v-list-item>
          <v-list-item title="Running:">
            {{ requestDetails.running_tasks }} Tasks
          </v-list-item>
          <v-list-item title="Pending:">
            {{ requestDetails.queued_tasks }} Tasks
          </v-list-item>
          <v-list-item title="Successful:">
            {{ requestDetails.successful_tasks }} Tasks
          </v-list-item>
          <v-list-item title="Failed:">
            {{ requestDetails.failed_tasks }} Tasks
          </v-list-item>
        </v-list-group>
      </v-list>
    </v-card>
    <request-report v-if="markdownReport !== ''" :markdownReport="this.markdownReport" :key="this.currentRequestID">
    </request-report>
  </div>
</template>

<script>
import ApiClient from '../utils/RestApiClient.js'
import { mergeProps } from 'vue'
import RequestReport from './RequestReport.vue';

export default {
  components: { RequestReport },
  props: ['requestDetails'],
  data() {
    return {
      openGroups: ['ids', 'details'],
      markdownReport: '',
      currentRequestID: ''
    }
  },
  methods: {
    mergeProps,
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
    getMarkdownReport: function (request_id) {
      ApiClient.getRequestReport(request_id)
        .then(({ data }) => {
          this.markdownReport = data
          // To allow for re-click if user requests same report
          if (this.currentRequestID === request_id) {
            this.currentRequestID = request_id + Math.random()
          } else {
            this.currentRequestID = request_id
          }
        })
        .catch((e) => {
          console.error(e)
        })
    },
  }
}
</script>

<style scoped>
.v-list-item {
  font-size: 12px;
}

.v-list-item__action {
  margin-top: 0;
  margin-bottom: 0;
}
</style>
