<template>
  <v-app id="app">
    <v-main>
      <v-btn @click="getRequest">Refresh</v-btn>
      <v-data-table :headers="headers" :items="requestSummary"></v-data-table>
    </v-main>
  </v-app>
</template>

<script>
import axios from 'axios'
export default {
  name: 'app',
  data() {
    return {
      headers: [
        { text: 'Last Task Update Time', value: 'last_task_update_time' },
        { text: 'Request ID', value: 'request_id' },
        { text: 'Requester', value: 'requester' },
        { text: 'Total Tasks', value: 'total_tasks' },
        { text: 'Running Tasks', value: 'running_tasks' },
        { text: 'Successful Tasks', value: 'successful_tasks' },
        { text: 'Failed Tasks', value: 'failed_tasks' },
        { text: 'Status', value: 'status' },
      ],
      requestSummary: [],
      message: 'Hello',
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
              last_task_update_time: data[req].last_task_update_time,
              request_id: data[req].request_id,
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
  },
  computed: {
    reverseMsg() {
      return ''
    },
  },
  mounted() {
    this.getRequest()
  },
}
</script>
