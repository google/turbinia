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
    <nav class="navbar">
      <v-app-bar app flat>
        <div class="turbinia-logo">
          <v-img src="./assets/turbinia-logo-mark.png" max-height="50" max-width="70" contain />
        </div>
        <div class="turbinia-title">
          <v-toolbar-title>Turbinia</v-toolbar-title>
        </div>
        <v-spacer></v-spacer>
        <div class="dark-theme-btn">
          <v-tooltip left>
            <template v-slot:activator="{ on, attrs }">
              <v-btn icon v-on:click="toggleTheme" v-bind="attrs" v-on="on">
                <v-icon>mdi-brightness-6</v-icon>
              </v-btn>
            </template>
            Switch to dark mode
          </v-tooltip>
        </div>
      </v-app-bar>
    </nav>
    <v-main>
      <div>
        <v-card>
          <v-card-title>
            Request List
            <v-spacer></v-spacer>
            <v-text-field
              v-model="search"
              append-icon="mdi-magnify"
              label="Search"
              single-line
              hide-details
            ></v-text-field>
            <v-spacer></v-spacer>
            <v-tooltip left>
              <template v-slot:activator="{ on, attrs }">
                <v-btn fab color="blue lighten-2" @click="getRequest()" v-bind="attrs" v-on="on">
                  <v-icon>mdi-refresh</v-icon>
                </v-btn>
              </template>
              Refresh Request List
            </v-tooltip>
          </v-card-title>
          <v-data-table
            :headers="headers"
            :items="this.requestSummary"
            :search="search"
            :footer-props="{ itemsPerPageOptions: [10, 20, 40, -1] }"
          >
          </v-data-table>
        </v-card>
      </div>
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
