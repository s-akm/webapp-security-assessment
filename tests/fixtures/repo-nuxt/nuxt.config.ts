export default defineNuxtConfig({
  modules: ['@nuxtjs/google-analytics'],
  runtimeConfig: { public: { NUXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY: '' } }
})
