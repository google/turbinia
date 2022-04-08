<template>
  <v-app id="turb">
    <v-navigation-drawer v-model="drawer" app class="pt-4" color="grey lighten-3" mini-variant>
      <v-avatar
        v-for="n in 6"
        :key="n"
        :color="`grey ${n === 1 ? 'darken' : 'lighten'}-1`"
        :size="n === 1 ? 36 : 20"
        class="d-block text-center mx-auto mb-9"
      ></v-avatar>
    </v-navigation-drawer>

    <v-main>
      <v-data-table :headers="headers"></v-data-table>
    </v-main>
  </v-app>
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
