<template>
    <b-navbar class="is-transparent">
        <template slot="start">
            <b-navbar-item tag="router-link" to="/">
                Home
            </b-navbar-item>
            <b-navbar-item tag="router-link" to="/about">
                About
            </b-navbar-item>
            <b-navbar-dropdown  v-if="isLoggedIn" label="More">
                <b-navbar-item tag="router-link" to="/protected">
                    Protected
                </b-navbar-item>
            </b-navbar-dropdown>
        </template>
        <template slot="end">
            <b-navbar-item tag="div">
                <div class="buttons">
                    <router-link v-if="!isLoggedIn" class="button is-warning" to="/register" >
                        Register
                    </router-link>
                    <router-link v-if="!isLoggedIn" class="button is-primary" to="/login">
                        Login
                    </router-link>
                    <button v-if="isLoggedIn" tag="router-link" @click="logout" class="button is-pending">
                        Log out
                    </button>
                </div>
            </b-navbar-item>
        </template>
    </b-navbar>
</template>

<script>
    export default {
        computed : {
            isLoggedIn(){ return this.$store.getters.isLoggedIn}
        },
        methods: {
            logout() {
                this.$store.dispatch('logout')
                    .then(() => {
                        this.$router.push('/login')
                    })
            }
        },
    }
</script>