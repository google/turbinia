<template>
  <v-data-table :headers="headers"></v-data-table>
</template>

<script>
export default {
  data() {
    return {
      headers: [
        {
          text: 'Request ID',
          align: 'start',
          value: 'name',
        },
        { text: 'Requester', value: 'requester' },
        { text: 'Created', value: 'created' },
        { text: 'Last Update Time', value: 'last_update_time' },
        { text: 'Status', value: 'status' },
      ],
    }
  },
}
</script>
