export async function GET() { await purgeOld(); return Response.json({}); }
