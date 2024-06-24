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
      <v-app-bar flat :elevation="1">
        <template v-slot:prepend>
          <v-img src="./turbinia-logo-mark.png" height="50" width="70"></v-img>
        </template>
        <v-app-bar-title>Turbinia</v-app-bar-title>
        <v-spacer></v-spacer>
        <div class="dark-theme-btn">
          <v-tooltip left>
            <template v-slot:activator="{ props }">
              <v-btn icon v-on:click="toggleTheme" v-bind="props">
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
              <task-details :taskDetails="taskDetails"></task-details>
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
import RequestList from './components/RequestList.vue'
import TaskDetails from './components/TaskDetails.vue'
import ApiClient from './utils/RestApiClient.js'

export function truncate(text, length, suffix) {
  if (text.length > length) {
    return text.substring(0, length) + suffix;
  } else {
    return text;
  }
}

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
}
</script>

<script setup>
import { useTheme } from 'vuetify'

const theme = useTheme()

function toggleTheme() {
  theme.global.name.value = theme.global.current.value.dark ? 'light' : 'dark'
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
