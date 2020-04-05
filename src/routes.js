import Home from './components/home'
import About from './components/About'
import Login from './components/auth/Login'
import Register from  './components/auth/Register'
import Protected from './components/Protected'
import {store} from "./store/store";

export const routes = [
    { path: '', component: Home },
    { path: '/login', component: Login },
    { path: '/about', component: About },
    { path: '/register', component: Register },
    {
        path: '/protected',
        component: Protected,
        beforeEnter: (to, from, next) => {
            if (store.getters.isLoggedIn) {
                next()
                return
            }
            next('/')
        }}
]

