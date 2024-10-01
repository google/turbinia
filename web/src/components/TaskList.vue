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
    <v-list density="compact">
      <v-empty-state v-if="taskList.length === 0" text="No Tasks are available. Try adjusting your filters.">
      </v-empty-state>
      <v-virtual-scroll :items="taskList" :item-height="40" :height="400" v-else>
        <template v-slot:default="{ item }">
          <v-list-item :key="item.task_id" v-slot:prepend>
            <div v-if="item.task_success">
              <v-list-item> <v-icon color="green" icon="mdi-check"> </v-icon> </v-list-item>
            </div>
            <div v-else-if="item.task_success === null">
              <v-list-item>
                <v-progress-circular indeterminate color="blue" :size="20"></v-progress-circular>
              </v-list-item>
            </div>
            <div v-else>
              <v-list-item> <v-icon color="red" icon="mdi-alert-circle"> </v-icon> </v-list-item>
            </div>
            <div>
              <v-list-item-action>
                <v-btn variant="text" :ripple="true" :key="item.task_id" selected-class="activated"
                  :class="{ activated: isActiveRow == item.task_id }"
                  @click="getTaskDetails(item.task_id) + selectActiveRow(item.task_id)">
                  {{ item.task_id }}
                </v-btn>
              </v-list-item-action>
            </div>
            <v-list-item :max-width="800">
              {{ item.task_name }} {{ $filters.truncate(item.task_status, 384, '...') }}
            </v-list-item>
          </v-list-item>
          <v-divider> </v-divider>
        </template>
      </v-virtual-scroll>
    </v-list>
  </div>
</template>

<script>
import ApiClient from '../utils/RestApiClient.js'

export default {
  props: ['requestId', 'filterFailed', 'filterSuccess', 'filterRunning', 'filterJobs', 'radioFilter', 'isActiveRow'],
  inject: ['getTaskDetails', 'selectActiveRow'],
  data() {
    return {
      headers: [
        { text: 'Task', value: 'task_name_id' },
        { text: 'Status', value: 'task_status' },
      ],
      taskList: [],
    }
  },
  methods: {
    getTaskList: function (request_id) {
      ApiClient.getTaskList(request_id)
        .then((response) => {
          let taskList = []
          let data = response.data['tasks']
          for (const task in data) {
            let task_dict = data[task]
            let taskStatusTemp = task_dict.celery_state
            // As pending status requests show as null or pending
            if (taskStatusTemp === null || taskStatusTemp === "PENDING") {
              taskStatusTemp = 'is pending on server.'
            }
            else if (taskStatusTemp == "RECEIVED") {
              taskStatusTemp = 'is queued for execution.'
            }
            else if (taskStatusTemp == "STARTED") {
              taskStatusTemp = 'is running on ' + task_dict.worker_name
            }
            else {
              taskStatusTemp = task_dict.status
            }
            if (this.filterJobs.length > 0) {
              let jobName = task_dict.job_name.toLowerCase()
              if (this.radioFilter && !this.filterJobs.includes(jobName)) {
                continue;
              } else if (!this.radioFilter && this.filterJobs.includes(jobName)) {
                continue
              }
            }
            let taskListTemp = {
              job_name: task_dict.job_name,
              task_name: task_dict.name,
              task_id: task_dict.id,
              task_status: taskStatusTemp,
              task_success: task_dict.successful,
              evidence_name: task_dict.evidence_name,
              evidence_id: task_dict.evidence_id,
              evidence_size: task_dict.evidence_size,
            }
            // When Failed filter chip is applied
            if (task_dict.successful === false && this.filterFailed) {
              taskList.push(taskListTemp)
            }
            // When Success filter chip is applied
            if (task_dict.successful && this.filterSuccess) {
              taskList.push(taskListTemp)
            }
            // When Running filter chip is applied
            if (task_dict.successful === null && this.filterRunning) {
              taskList.push(taskListTemp)
            }
            // When no filter chip is applied
            if (!this.filterRunning && !this.filterSuccess && !this.filterFailed) {
              taskList.push(taskListTemp)
            }
          }
          // Sort by task name
          taskList = taskList.sort((a, b) => (a.task_name > b.task_name ? 1 : -1))
          this.taskList = taskList
        })
        .catch((e) => {
          console.error(e)
        })
    },
  },
  created() {
    this.getTaskList(this.requestId)
  },
}
</script>

<style scoped>
.v-btn {
  font-family: 'Roboto Mono', monospace;
  font-weight: 500;
}

.v-item {
  font-family: 'Roboto Mono', monospace;
}

.activated {
  background-color: rgba(128, 128, 128, 0.4);
}
</style>
