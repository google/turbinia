<template>
  <td :colspan="requestHeaders.length">
    <v-data-table :headers="headers" :items="taskList" dense :item-key="task_id"> </v-data-table>
  </td>
</template>

<script>
import ApiClient from '../utils/RestApiClient.js'

export default {
  props: ['requestHeaders', 'requestId'],
  data() {
    return {
      headers: [
        { text: 'Task', value: 'task_name_id' },
        { text: 'Status', value: 'task_status' },
      ],
      taskList: [],
    }
  },
  methods: {
    retrieveTaskList: function (request_id) {
      ApiClient.getTaskList(request_id)
        .then((response) => {
          let taskList = []
          let data = response.data['tasks']
          for (const task in data) {
            let task_dict = data[task]
            taskList.push({
              task_name_id: task_dict.name + ' ( ' + task_dict.id + ' )',
              task_id: task_dict.id,
              task_name: task_dict.name,
              task_status: task_dict.status,
            })
          }
          this.taskList = taskList
        })
        .catch((e) => {
          console.error(e)
        })
    },
  },
  created() {
    this.retrieveTaskList(this.requestId)
  },
  computed: {
    items() {
      return Array.from({ length: 200 }, (k, v) => v + 1)
    },
  },
}
</script>
