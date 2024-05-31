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
      <v-virtual-scroll :items="taskList" :item-height="40" :height="400" :width="auto">
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
                  :class="{ activated: isActive == item.task_id }"
                  @click="getTaskDetails(item.task_id) + selectActiveStatus(item.task_id)">
                  {{ item.task_id }}
                </v-btn>
              </v-list-item-action>
            </div>
            <v-list-item>
              {{ item.task_name }} {{ $filters.truncate(item.task_status, 128, '...') }}
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
  props: ['requestId'],
  inject: ['getTaskDetails'],
  data() {
    return {
      headers: [
        { text: 'Task', value: 'task_name_id' },
        { text: 'Status', value: 'task_status' },
      ],
      taskList: [],
      isActive: false,
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
            taskList.push({
              task_name: task_dict.name,
              task_id: task_dict.id,
              task_status: task_dict.status,
              task_success: task_dict.successful,
              evidence_name: task_dict.evidence_name,
              evidence_id: task_dict.evidence_id,
              evidence_size: task_dict.evidence_size,
            })
          }
          this.taskList = taskList
        })
        .catch((e) => {
          console.error(e)
        })
    },
    selectActiveStatus: function (task_id) {
      this.isActive = task_id
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
