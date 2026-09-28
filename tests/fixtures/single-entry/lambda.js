exports.handler = async (event) => {
  if (event.routeKey === 'GET /members') {
    const user = await verifyToken(event.headers.authorization);
    if (!user) return { statusCode: 401 };
    return { statusCode: 200, body: '[]' };
  }
  if (event.path.startsWith('/exports')) {
    return { statusCode: 200, body: await buildCsv() };
  }
  return { statusCode: 404 };
};
