const state = {
    status: '',
    token: localStorage.getItem('token' || ''),
    user: null
}

const getters = {
    isLoggedIn: state => !!state.token,
    authStatus: state => state.status
}

const mutations = {
    AUTH_REQUEST (state){
        state.status = 'loading'
    },
    AUTH_SUCCESS (state, token, user){
        state.status = 'success'
        state.token = token
        state.user = user
    },
    AUTH_ERROR (state){
        state.status = 'error'
    },
    LOGOUT (state){
        state.status = ''
        state.token = ''
    }
}

const actions = {
    login ({commit}, user) {
        return new Promise((resolve, reject) => {
            commit('AUTH_REQUEST')
            axios({url: '/api/login', data: user, method: 'POST' })
                .then(resp => {
                    const token = resp.data.token
                    const user = resp.data
                    localStorage.setItem('token', token)
                    axios.defaults.headers.common['Authorization'] = token
                    commit('AUTH_SUCCESS', token, user)
                    resolve(resp)
                })
                .catch(err => {
                    commit('AUTH_ERROR')
                    localStorage.removeItem('token')
                    reject(err)
                })
        })
    },

    register ({commit}, user) {
        return new Promise((resolve, reject) => {
            commit('AUTH_REQUEST')
            axios({url: '/api/register', data: user, method: 'POST' })
                .then(resp => {
                    const token = resp.data.token
                    const user = resp.data
                    localStorage.setItem('token', token)
                    axios.defaults.headers.common['Authorization'] = token
                    commit('AUTH_SUCCESS', token, user)
                    resolve(resp)
                })
                .catch(err => {
                    commit('AUTH_ERROR', err)
                    localStorage.removeItem('token')
                    reject(err)
                })
        })
    },

    logout ({commit}) {
        return new Promise((resolve, reject) => {
            commit('LOGOUT')
            localStorage.removeItem('token')
            delete axios.defaults.headers.common['Authorization']
            resolve()
        })
    }
}

export default {
    state,
    getters,
    mutations,
    actions
}