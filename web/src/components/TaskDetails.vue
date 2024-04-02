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
      {{ taskDetails.name }}
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
    </v-card-title>
    <v-alert v-if="taskDetails.successful === true" type="success" prominent>
      {{ taskDetails.status }}
    </v-alert>
    <v-alert v-else-if="taskDetails.successful === null" type="info" prominent>
      {{ taskDetails.status }}
    </v-alert>
    <v-alert v-else type="error" prominent>
      {{ taskDetails.status }}
    </v-alert>
    <v-card>
      <v-list v-model:opened="openGroups">
        <v-list-group value="ids">
          <template v-slot:activator="{ props }">
            <v-list-item v-bind="props" title="Associated IDs"></v-list-item>
          </template>
          <v-list-item title="Task ID:">
            {{ taskDetails.id }}
          </v-list-item>
          <v-list-item title="Request ID:">
            {{ taskDetails.request_id }}
          </v-list-item>
          <v-list-item title="Evidence ID:">
            {{ taskDetails.evidence_id }}
          </v-list-item>
          <v-list-item title="Group ID:">
            {{ taskDetails.group_id }}
          </v-list-item>
          <v-list-item title="Job ID:">
            {{ taskDetails.job_id }}
          </v-list-item>
        </v-list-group>
        <v-list-group value="details">
          <template v-slot:activator="{ props }">
            <v-list-item v-bind="props" title="Processing Details"></v-list-item>
          </template>
          <v-list-item title="Evidence Name:">
            {{ taskDetails.evidence_name }}
          </v-list-item>
          <v-list-item title="Evidence Size:">
            {{ taskDetails.evidence_size }} bytes
          </v-list-item>
          <v-list-item title="Arguments:">
            {{ taskDetails.all_args }}
          </v-list-item>
          <v-list-item title="Last Update:">
            {{ taskDetails.last_update }}
          </v-list-item>
          <v-list-item title="Requester:">
            {{ taskDetails.requester }}
          </v-list-item>
          <v-list-item title="Worker:">
            {{ taskDetails.worker_name }}
          </v-list-item>
          <v-list-item title="Successful:">
            {{ taskDetails.successful }}
          </v-list-item>
          <v-list-item title="Run Time:">
            {{ taskDetails.run_time }} seconds
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
  </div>
</template>

<script>
import ApiClient from '../utils/RestApiClient.js'
import { mergeProps } from 'vue'

export default {
  props: ['taskDetails'],
  data() {
    return {
      openGroups: ['ids', 'details'],
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
