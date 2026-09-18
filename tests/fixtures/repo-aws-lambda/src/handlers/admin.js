// API Gateway + Lambda。ガードあり
exports.handler = async (event) => {
  const user = await requireAuth(event.headers.Authorization);
  if (!user) return { statusCode: 401, body: 'no' };
  return { statusCode: 200, body: '{}' };
};
