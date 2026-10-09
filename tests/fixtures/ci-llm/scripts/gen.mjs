// 記事を生成して CMS へ公開する（題材）
const res = await fetch("https://api.anthropic.com/v1/messages", { method: "POST", headers: { "x-api-key": process.env.LLM_KEY } });
const body = await res.json();
await fetch(process.env.CMS_URL, { method: "PUT", headers: { authorization: process.env.CMS_TOKEN }, body: JSON.stringify({ html: body }) });
