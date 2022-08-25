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
      <request-list></request-list>
    </v-main>
  </v-app>
</template>

<script>
import RequestList from './components/RequestList'

export default {
  name: 'app',
  components: { RequestList },
  data() {
    return {}
  },
  methods: {
    toggleTheme: function () {
      this.$vuetify.theme.dark = !this.$vuetify.theme.dark
      localStorage.setItem('isDarkTheme', this.$vuetify.theme.dark.toString())
    },
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
