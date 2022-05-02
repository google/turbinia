import Vue from 'vue'
import App from './App.vue'
import vuetify from './plugins/vuetify'

// Disable warning during development
Vue.config.productionTip = false

new Vue({
  vuetify,
  render: (h) => h(App),
}).$mount('#app')
