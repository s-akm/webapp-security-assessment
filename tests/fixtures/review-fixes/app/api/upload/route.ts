export async function POST(req) { const fd = await req.formData(); const f = fd.get('file') as File; return new Response('ok'); }
