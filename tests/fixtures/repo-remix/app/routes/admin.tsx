export async function loader({ request }) {
  const user = await requireUser(request);
  return json({ user });
}
