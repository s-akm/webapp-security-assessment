export async function GET() {
  return new Response('data: hi\n\n', { headers: { 'Content-Type': 'text/event-stream' } });
}
