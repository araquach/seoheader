<template>
    <div class="section columns">
        <div class="column is-7">
            <div class="box is-shadowless">
                <div class="columns">
                    <div class="column">
                        <h3 class="title is-4">Register</h3>
                    </div>
                </div>
                <form @submit.prevent="register">
                    <div>
                        <b-field label="Full Name"
                                 :type="{ 'is-danger': $v.name.$error }"
                                 :message="{'Full Name is required' : !$v.name.required}">
                            <b-input v-model.trim="$v.name.$model"
                                     placeholder="Full Name">
                            </b-input>
                        </b-field>
                        <b-field label="Email Address"
                                 :type="{ 'is-danger': $v.email.$error }"
                                 :message="[{'Email address is required' : !$v.email.required}, {'Provide a valid email address' : !$v.email.email}]">
                            <b-input v-model.trim="$v.email.$model"
                                     placeholder="Email">
                            </b-input>
                        </b-field>
                        <b-field label="Password"
                                 :type="{ 'is-danger': $v.password.$error }"
                                 :message="{'Password is required' : !$v.password.required}">
                            <b-input v-model.trim="$v.password.$model"
                                     placeholder="Password">
                            </b-input>
                        </b-field>
                        <br>
                        <div class="field">
                            <div class="control">
                                <button class="button" type="submit" :disabled="submitStatus === 'PENDING'">Register</button>
                            </div>
                        </div>
                    </div>
                </form>
            </div>
        </div>
    </div>
</template>

<script>
    import {required, email} from 'vuelidate/lib/validators'
    export default {
        data(){
            return {
                name : "",
                email : "",
                password : "",
                is_admin : null,
                submitStatus: null
            }
        },

        validations: {
            name: { required },
            email: { required, email },
            password: { required }
        },

        methods: {
            register() {
                const data = {
                    name: this.name,
                    email: this.email,
                    password: this.password,
                    is_admin: this.is_admin
                }
                this.$v.$touch()
                if (!this.$v.$invalid) {
                    this.$store.dispatch('register', data)
                        .then(response => {
                            this.submitStatus = 'OK'
                        })
                    this.$router.push('/login')
                        .catch((e) => {
                            console.error(e)
                        })
                }
            }
        }
    }
</script>