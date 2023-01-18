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
      <v-tooltip top>
        Download Task output
        <template v-slot:activator="{ on, attrs }">
          <v-btn icon v-on="on" v-bind="attrs" @click="getTaskOutput(taskDetails.id)">
            <v-icon> mdi-file-download-outline </v-icon>
          </v-btn>
        </template>
      </v-tooltip>
    </v-card-title>
    <v-alert v-if="taskDetails.successful === true" type="success" border="bottom" colored-border>
      {{ taskDetails.status }}
    </v-alert>
    <v-alert v-else-if="taskDetails.successful === null" type="info" border="bottom" colored-border>
      {{ taskDetails.status }}
    </v-alert>
    <v-alert v-else type="error" border="bottom" colored-border>
      {{ taskDetails.status }}
    </v-alert>
    <v-card>
      <v-list dense>
        <v-list-group :value="true">
          <template v-slot:activator>
            <v-list-item-title>Associated IDs</v-list-item-title>
          </template>
          <v-list-item>
            <v-list-item-content>
              <v-list-item-title> Task ID: </v-list-item-title>
              {{ taskDetails.id }}
            </v-list-item-content>
          </v-list-item>
          <v-list-item>
            <v-list-item-content>
              <v-list-item-title> Request ID: </v-list-item-title>
              {{ taskDetails.request_id }}
            </v-list-item-content>
          </v-list-item>
          <v-list-item>
            <v-list-item-content>
              <v-list-item-title> Group ID: </v-list-item-title> {{ taskDetails.group_id }}
            </v-list-item-content>
          </v-list-item>
          <v-list-item>
            <v-list-item-content>
              <v-list-item-title> Job ID: </v-list-item-title>{{ taskDetails.job_id }}
            </v-list-item-content>
          </v-list-item>
        </v-list-group>
        <v-list-group :value="true">
          <template v-slot:activator>
            <v-list-item-title>Processing Details</v-list-item-title>
          </template>
          <v-list-item>
            <v-list-item-content>
              <v-list-item-title> Evidence Name: </v-list-item-title>
              {{ taskDetails.evidence_name }}
            </v-list-item-content>
          </v-list-item>
          <v-list-item>
            <v-list-item-content>
              <v-list-item-title> Arguments: </v-list-item-title> {{ taskDetails.all_args }}
            </v-list-item-content>
          </v-list-item>
          <v-list-item>
            <v-list-item-content>
              <v-list-item-title> Last Update: </v-list-item-title> {{ taskDetails.last_update }}
            </v-list-item-content>
          </v-list-item>
          <v-list-item>
            <v-list-item-content>
              <v-list-item-title> Requester: </v-list-item-title>{{ taskDetails.requester }}
            </v-list-item-content>
          </v-list-item>
          <v-list-item>
            <v-list-item-content>
              <v-list-item-title> Worker: </v-list-item-title>{{ taskDetails.worker_name }}
            </v-list-item-content>
          </v-list-item>
          <v-list-item>
            <v-list-item-content>
              <v-list-item-title> Successful: </v-list-item-title>{{ taskDetails.successful }}
            </v-list-item-content>
          </v-list-item>
          <v-list-item>
            <v-list-item-content>
              <v-list-item-title> Run Time: </v-list-item-title>{{ taskDetails.run_time }} seconds
            </v-list-item-content>
          </v-list-item>
        </v-list-group>
        <div v-if="taskDetails.saved_paths">
          <v-list-group :value="false">
            <template v-slot:activator>
              <v-list-item-title>Saved Paths: </v-list-item-title>
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

export default {
  props: ['taskDetails'],
  data() {
    return {}
  },
  methods: {
    getTaskOutput: function (task_id) {
      ApiClient.getTaskOutput(task_id)
        .then(({ data }) => {
          const downloadObj = window.URL.createObjectURL(new Blob([data]))
          const link = document.createElement('a')
          link.href = downloadObj
          link.setAttribute('download', task_id + '.zip')
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
