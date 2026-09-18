// ガードなし
export default defineEventHandler(async (event) => {
  const body = await readBody(event)
  await sendMail(body.email)
  return { ok: true }
})
