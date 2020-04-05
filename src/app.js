import Vue from 'vue'
import VueRouter from 'vue-router'
import Vuelidate from 'vuelidate'
import App from './App.vue'
import { routes } from "./routes"
import { store } from './store/store'

import Buefy from 'buefy'
Vue.use(Buefy)

Vue.use(Vuelidate)
Vue.use(VueRouter)


window.axios = require('axios')

const router = new VueRouter({
    mode: 'history',
    routes
})

router.beforeEach((to, from, next) => {
    if(to.matched.some(record => record.meta.requiresAuth)) {
        if (store.getters.isLoggedIn) {
            next()
            return
        }
        next('/')
    } else {
        next()
    }
})

new Vue({
    el: '#app',
    router,
    store,
    render: h => h(App)
})