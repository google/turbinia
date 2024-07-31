<!--
Copyright 2024 Google Inc. All rights reserved.
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
  <section>
    <div class="text-center pa-4">
      <v-dialog v-model="openReportDialog" width="auto">
        <v-card class="markdown-body pa-4 ps-12 ga-3" v-html="sanitizeHtml(this.markdownReport)"></v-card>
      </v-dialog>
    </div>
  </section>
</template>

<script>
import DOMPurify from 'dompurify'
import { marked } from 'marked'

export default {
  props: ['markdownReport'],
  data() {
    return {
      openReportDialog: false,
    }
  },
  methods: {
    sanitizeHtml(html) {
      return DOMPurify.sanitize(marked(html))
    },
  },
  mounted() {
    this.openReportDialog = true
  },
  beforeUnmount() {
    this.openReportDialog = false
  },
}
</script>

<style scoped>

.markdown-body {
  max-width: 125ch;
}

</style>