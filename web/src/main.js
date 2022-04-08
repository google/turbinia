import Vue from 'vue'
import App from './App.vue'
import vuetify from './plugins/vuetify'
import RequestList from './components/RequestList.vue'

Vue.component('request-list', RequestList)

// Disable warning during development
Vue.config.productionTip = false

new Vue({
  vuetify,
  render: (h) => h(App),
}).$mount('#app')
