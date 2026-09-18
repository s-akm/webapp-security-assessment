export async function action({ request }) {
  const form = await request.formData();
  await sendMail(form.get('email'));
  return json({ ok: true });
}
