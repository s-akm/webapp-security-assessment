// ガードあり（Nuxt / Nitro）
export default defineEventHandler(async (event) => {
  const user = await requireUserSession(event)
  if (!user.isAdmin) throw createError({ statusCode: 403 })
  return await db.from('users').select('id')
})
