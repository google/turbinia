<template>
  <v-app id="turb2">
    <v-btn @click="count++">Refresh</v-btn>
    <v-data-table :headers="headers" :items="requestSummary"></v-data-table>
  </v-app>
</template>

<script>
export default {
  data() {
    return {
      headers: [
        { text: 'Request ID', value: 'request_id' },
        { text: 'Requester', value: 'requester' },
        { text: 'Created', value: 'created' },
        { text: 'Last Update Time', value: 'last_update_time' },
        { text: 'Status', value: 'status' },
      ],
      requestSummary: [],
      count: 0,
    }
  },
  computed: {
    getRequestStatus() {
      console.log('test')
      return ''
    },
  },
}
</script>
