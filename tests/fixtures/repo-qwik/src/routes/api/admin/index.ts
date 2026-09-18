export const onGet = async ({ sharedMap, json }) => {
  const user = sharedMap.get('user');
  if (!user) throw json(401, { error: 'no' });
  json(200, { ok: true });
};
