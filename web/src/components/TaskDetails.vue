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
  <div>
    <v-card-title>
      Task Details
      <v-snackbar timeout="5000" color="primary" location="top" height="55">
        Task output is <strong>downloading in the background</strong>, please wait
        <v-progress-circular color="white" indeterminate></v-progress-circular>
        <template v-slot:activator="{ props: snackbar }">
          <v-tooltip top text="Download task output">
            <template v-slot:activator="{ props: tooltip }">
              <v-btn icon v-bind="mergeProps(snackbar, tooltip)" @click="getTaskOutput(taskDetails.id)">
                <v-icon> mdi-file-download-outline </v-icon>
              </v-btn>
            </template>
          </v-tooltip>
        </template>
      </v-snackbar>
      <v-tooltip location="top" text="View task report">
        <template v-slot:activator="{ props: tooltip }">
          <v-btn icon="mdi-file-document-outline" variant="text" v-bind="tooltip"
            @click="getMarkdownReport(taskDetails.id)">
          </v-btn>
        </template>
      </v-tooltip>
    </v-card-title>
    <v-alert v-if="taskDetails.successful === true" type="success" prominent>
      {{ taskDetails.status }}
    </v-alert>
    <v-alert v-else-if="taskDetails.successful === false" type="error" prominent>
      {{ taskDetails.status }}
    </v-alert>
    <v-alert v-else-if="taskDetails.celery_state === 'STARTED'" type="info" prominent>
      Task {{ taskDetails.id }} is running on {{ taskDetails.worker_name }}
    </v-alert>
    <v-alert v-else-if="taskDetails.celery_state === 'PENDING'" type="info" prominent>
      Task {{ taskDetails.id }} is pending.
    </v-alert>
    <v-alert v-else-if="taskDetails.celery_state === 'RECEIVED'" type="info" prominent>
      Task {{ taskDetails.id }} is queued.
    </v-alert>
    <v-alert v-else type="error" prominent>
      {{ taskDetails.status }}
    </v-alert>
    <v-card>
      <v-list density="compact" v-model:opened="openGroups">
        <v-list-group value="ids">
          <template v-slot:activator="{ props }">
            <v-list-item v-bind="props" title="Associated IDs"></v-list-item>
          </template>
          <v-list-item title="Task ID:">
            <div v-if="taskDetails.id">
              {{ taskDetails.id }}
            </div>
            <div v-else>N/A</div>
          </v-list-item>
          <v-list-item title="Request ID:">
            <div v-if="taskDetails.request_id">
              {{ taskDetails.request_id }}
            </div>
            <div v-else>N/A</div>
          </v-list-item>
          <v-list-item title="Celery ID:">
            <div v-if="taskDetails.celery_id">
              {{ taskDetails.celery_id }}
            </div>
            <div v-else>N/A</div>
          </v-list-item>
          <v-list-item title="Celery State:">
            <div v-if="taskDetails.celery_state">
              {{ taskDetails.celery_state }}
            </div>
            <div v-else>N/A</div>
          </v-list-item>
          <v-list-item title="Evidence ID:">
            <div v-if="taskDetails.evidence_id">
              {{ taskDetails.evidence_id }}
            </div>
            <div v-else>N/A</div>
          </v-list-item>
          <v-list-item title="Group ID:">
            <div v-if="taskDetails.group_id">
              {{ taskDetails.group_id }}
            </div>
            <div v-else>N/A</div>
          </v-list-item>
          <v-list-item title="Job ID:">
            <div v-if="taskDetails.job_id">
              {{ taskDetails.job_id }}
            </div>
            <div v-else>N/A</div>
          </v-list-item>
        </v-list-group>
        <v-list-group value="details">
          <template v-slot:activator="{ props }">
            <v-list-item v-bind="props" title="Processing Details"></v-list-item>
          </template>
          <v-list-item title="Task Name:">
            <div v-if="taskDetails.name">
              {{ taskDetails.name }}
            </div>
            <div v-else>N/A</div>
          </v-list-item>
          <v-list-item title="Job Name:">
            <div v-if="taskDetails.job_name">
              {{ taskDetails.job_name }}
            </div>
            <div v-else>N/A</div>
          </v-list-item>
          <v-list-item title="Evidence Name:">
            <template v-if="taskDetails.evidence_name" v-slot:append>
              <v-tooltip location="top" text="Download Evidence output">
                <template v-slot:activator="{ props: tooltip }">
                  <v-btn icon="mdi-magnify-plus" v-bind="tooltip" @click="downloadEvidence(taskDetails.evidence_id)">
                  </v-btn>
                </template>
              </v-tooltip>
            </template>
            <v-snackbar v-model="evidenceSnackbar" color="primary" location="top" height="55" timeout="2000">
              Evidence output is downloading...
            </v-snackbar>
            <v-snackbar v-model="notCopyable" color="red" location="top" height="55" timeout="2000">
              Evidence type is not supported for downloading.
            </v-snackbar>
            <div v-if="taskDetails.evidence_name">
              {{ taskDetails.evidence_name }}
            </div>
            <div v-else>N/A</div>
          </v-list-item>
          <v-list-item title="Evidence Size:">
            <div v-if="taskDetails.evidence_size">
              {{ taskDetails.evidence_size }} bytes
            </div>
            <div v-else>N/A</div>
          </v-list-item>
          <v-list-item title="Last Update:">
            <div v-if="taskDetails.last_update">
              {{ taskDetails.last_update }}
            </div>
            <div v-else>N/A</div>
          </v-list-item>
          <v-list-item title="Requester:">
            <div v-if="taskDetails.requester">
              {{ taskDetails.requester }}
            </div>
            <div v-else>N/A</div>
          </v-list-item>
          <v-list-item title="Worker:">
            <template v-if="taskDetails.worker_name" v-slot:append>
              <v-tooltip location="top" text="Download Worker Logs (defaults to most recent 500 entries)">
                <template v-slot:activator="{ props: tooltip }">
                  <v-btn icon="mdi-database-outline" v-bind="tooltip"
                    @click="downloadWorkerLogs(taskDetails.worker_name)">
                  </v-btn>
                </template>
              </v-tooltip>
            </template>
            <div v-if="taskDetails.worker_name">
              {{ taskDetails.worker_name }}
            </div>
            <div v-else>N/A</div>
          </v-list-item>
          <v-list-item title="Successful:">
            <div v-if="taskDetails.successful">
              {{ taskDetails.successful }}
            </div>
            <div v-else-if="taskDetails.successful == false">
              False
            </div>
            <div v-else>N/A</div>
          </v-list-item>
          <v-list-item title="Run Time:">
            <div v-if="taskDetails.run_time">
              {{ taskDetails.run_time }} seconds
            </div>
            <div v-else>N/A</div>
          </v-list-item>
        </v-list-group>
        <div v-if="taskDetails.saved_paths">
          <v-list-group>
            <template v-slot:activator="{ props }">
              <v-list-item v-bind="props" title="Saved Paths:"></v-list-item>
            </template>
            <v-list-item dense v-for="(path, idx) in taskDetails.saved_paths" :key="idx">
              {{ path }}
            </v-list-item>
          </v-list-group>
        </div>
      </v-list>
    </v-card>
    <request-report v-if="markdownReport !== ''" :markdownReport="this.markdownReport" :key="this.currentTaskID">
    </request-report>
  </div>
</template>

<script>
import ApiClient from '../utils/RestApiClient.js'
import { mergeProps } from 'vue'
import RequestReport from './RequestReport.vue';

export default {
  components: { RequestReport },
  props: ['taskDetails'],
  data() {
    return {
      openGroups: ['ids', 'details'],
      markdownReport: '',
      currentTaskID: '',
      evidenceSnackbar: false,
      notCopyable: false,
      openReportDialog: false,
    }
  },
  methods: {
    mergeProps,
    getTaskOutput: function (task_id) {
      ApiClient.getTaskOutput(task_id)
        .then(({ data }) => {
          const downloadObj = window.URL.createObjectURL(new Blob([data]))
          const link = document.createElement('a')
          link.href = downloadObj
          link.setAttribute('download', task_id + '.tgz')
          document.body.appendChild(link)
          link.click()
          link.remove()
        })
        .catch((e) => {
          console.error(e)
        })
    },
    getMarkdownReport: function (task_id) {
      ApiClient.getTaskReport(task_id)
        .then(({ data }) => {
          this.markdownReport = data
          // To allow for re-click if user requests same report
          if (this.currentTaskID === task_id) {
            this.currentTaskID = task_id + Math.random()
          } else {
            this.currentTaskID = task_id
          }
        })
        .catch((e) => {
          console.error(e)
        })
    },
    downloadEvidence: function (evidence_id) {
      ApiClient.downloadEvidence(evidence_id)
        .then(({ data }) => {
          this.evidenceSnackbar = true
          const downloadObj = window.URL.createObjectURL(new Blob([data]))
          const link = document.createElement('a')
          link.href = downloadObj
          link.setAttribute('download', evidence_id)
          document.body.appendChild(link)
          link.click()
          link.remove()
        })
        .catch((e) => {
          console.error(e)
          this.evidenceSnackbar = false
          this.notCopyable = true
        })
    },
    downloadWorkerLogs: function (worker_name) {
      ApiClient.getWorkerLogs(worker_name)
        .then(({ data }) => {
          const downloadObj = window.URL.createObjectURL(new Blob([data]))
          const link = document.createElement('a')
          link.href = downloadObj
          link.setAttribute('download', worker_name + '.log')
          document.body.appendChild(link)
          link.click()
          link.remove()
        })
        .catch((e) => {
          console.error(e)
        })
    },
  },
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
