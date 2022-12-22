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
            Toggle dark mode
          </v-tooltip>
        </div>
      </v-app-bar>
    </nav>
    <v-main>
      <v-container fluid>
        <v-row class="justify-center align-center">
          <v-col cols="9" align-self="start">
            <v-sheet rounded>
              <request-list></request-list>
            </v-sheet>
          </v-col>
          <v-col cols="3" align-self="start">
            <v-card rounded v-if="Object.keys(taskDetails).length">
              <task-details :taskDetails="this.taskDetails"></task-details>
            </v-card>
            <v-card rounded v-else>
              <v-card-title> Task Details </v-card-title>
              <v-card-subtitle> No Task Selected. Please click on a Task ID to see its details. </v-card-subtitle>
            </v-card>
          </v-col>
        </v-row>
      </v-container>
    </v-main>
  </v-app>
</template>

<script>
import RequestList from './components/RequestList'
import TaskDetails from './components/TaskDetails'
import ApiClient from './utils/RestApiClient.js'

export default {
  name: 'app',
  components: { RequestList, TaskDetails },
  provide() {
    return {
      getTaskDetails: this.getTaskDetails,
    }
  },
  data() {
    return {
      taskDetails: {},
    }
  },
  methods: {
    toggleTheme: function () {
      this.$vuetify.theme.dark = !this.$vuetify.theme.dark
      localStorage.setItem('isDarkTheme', this.$vuetify.theme.dark.toString())
    },
    getTaskDetails: function (task_id) {
      ApiClient.getTaskDetails(task_id)
        .then((response) => {
          this.taskDetails = response.data
        })
        .catch((e) => {
          console.error(e)
        })
    },
  },
  mounted() {
    const isDark = localStorage.getItem('isDarkTheme')
    if (isDark) {
      if (isDark === 'true') {
        this.$vuetify.theme.dark = true
      } else {
        this.$vuetify.theme.dark = false
      }
    }
  },
}
</script>

<style>
html,
body {
  height: 100%;
  overflow: auto;
  font-family: 'Roboto';
}
</style>
