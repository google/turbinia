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
  <v-app id="app">
    <v-app-bar app clipped-right flat>
      <v-img src="/turbinia-logo.png" max-height="80" max-width="80" contain></v-img>
      <v-tooltip right>
        <template v-slot:activator="{ on, attrs }">
          <v-btn icon v-on:click="toggleTheme" v-bind="attrs" v-on="on">
            <v-icon>mdi-brightness-6</v-icon>
          </v-btn>
        </template>
      </v-tooltip>
    </v-app-bar>
    <v-main>
      <v-col class="text-right">
        <v-btn @click="getRequest()">Refresh</v-btn>
      </v-col>
      <v-data-table :headers="headers" :items="outputRequest"></v-data-table>
    </v-main>
  </v-app>
</template>

<script>
import axios from 'axios'
export default {
  name: 'app',
  data() {
    return {
      search: '',
      headers: [
        { text: 'Request ID', value: 'request_id' },
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
    getRequest() {
      axios
        .get('http://localhost:8000/request/summary')
        .then((response) => {
          if (response.status === 200) {
            return response.data['requests_status']
          }
        })
        .then((data) => {
          var requestSummary = []
          for (const req in data) {
            requestSummary.push({
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
        .catch(function (error) {
          console.log(error)
        })
    },
    toggleTheme: function () {
      console.log('Switching theme')
      this.$vuetify.theme.dark = !this.$vuetify.theme.dark
      localStorage.setItem('isDarkTheme', this.$vuetify.theme.dark.toString())
    },
  },
  computed: {
    outputRequest() {
      return this.requestSummary
    },
  },
  mounted() {
    this.getRequest()
  },
}
</script>

<style>
html,
body {
  height: 100%;
  overflow: auto;
  font-family: 'Arial';
}
</style>
