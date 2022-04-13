<template>
  <v-data-table :headers="headers" :items="requestSummary"></v-data-table>
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
      requestSummary: [{ request_id: 'test1', last_update_time: '2' }, { request_id: 'test2' }],
    }
  },
}
</script>
