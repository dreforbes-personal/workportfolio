/**
 * Ask-About-Dre — Cloudflare Worker proxy for the Anthropic Messages API.
 *
 * DEPLOY (one-time, ~5 min):
 *   1. Sign in at https://dash.cloudflare.com — if you don't have an account, create one (free).
 *   2. Workers & Pages → Create → Create Worker.
 *   3. Name it something like "askdre-proxy". Click Deploy.
 *   4. Click "Edit code". Replace the default with this whole file. Click Deploy.
 *   5. Settings → Variables and Secrets → Add variable:
 *        Type:   Secret
 *        Name:   ANTHROPIC_API_KEY
 *        Value:  sk-ant-...   (your key from console.anthropic.com)
 *      Click Save and Deploy.
 *   6. Copy the worker URL (looks like https://askdre-proxy.<your-account>.workers.dev).
 *   7. Open https://dreforbes-personal.github.io/workportfolio/settings.html ,
 *      enter the password, paste that worker URL into "Worker endpoint", save.
 *   8. Done. The chat now uses your worker for any visitor.
 *
 * COST: Anthropic billing only — Claude Haiku 4.5 chats are fractions of a cent each.
 *       Cloudflare Workers free tier covers 100k requests/day, plenty for a portfolio.
 *
 * SECURITY:
 *   - Allowed origins are listed in ALLOWED_ORIGINS below. Other origins are rejected.
 *   - Per-IP rate limit (in-memory, best-effort): MAX_REQUESTS per WINDOW_MS.
 *   - Max body size enforced.
 *   - Optional shared-secret check (X-Ask-Token header) if you set ASK_TOKEN as a worker secret.
 */

const ALLOWED_ORIGINS = [
  'https://dreforbes-personal.github.io',
  // add http://localhost:3000 etc. here for local testing if needed
];

const MAX_BODY_BYTES = 32 * 1024;          // ~32 KB per request
const RATE_LIMIT_MAX = 30;                  // requests per window
const RATE_LIMIT_WINDOW_MS = 60 * 1000;     // 1 minute

const ipBuckets = new Map(); // very simple in-memory rate limiter — best-effort only

function corsHeaders(origin) {
  const allow = ALLOWED_ORIGINS.includes(origin) ? origin : 'null';
  return {
    'Access-Control-Allow-Origin': allow,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Ask-Token',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}

function jsonResponse(body, status, origin) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders(origin) },
  });
}

function rateLimited(ip) {
  const now = Date.now();
  let bucket = ipBuckets.get(ip);
  if (!bucket || now - bucket.start > RATE_LIMIT_WINDOW_MS) {
    bucket = { start: now, count: 0 };
    ipBuckets.set(ip, bucket);
  }
  bucket.count++;
  return bucket.count > RATE_LIMIT_MAX;
}

export default {
  async fetch(request, env, ctx) {
    const origin = request.headers.get('Origin') || '';
    const method = request.method;

    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }
    if (method !== 'POST') {
      return jsonResponse({ error: 'method_not_allowed' }, 405, origin);
    }
    if (!ALLOWED_ORIGINS.includes(origin)) {
      return jsonResponse({ error: 'origin_not_allowed', origin }, 403, origin);
    }

    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    if (rateLimited(ip)) {
      return jsonResponse({ error: 'rate_limited' }, 429, origin);
    }

    if (env.ASK_TOKEN) {
      const provided = request.headers.get('X-Ask-Token');
      if (provided !== env.ASK_TOKEN) {
        return jsonResponse({ error: 'unauthorized' }, 401, origin);
      }
    }

    let payload;
    try {
      const raw = await request.text();
      if (raw.length > MAX_BODY_BYTES) {
        return jsonResponse({ error: 'payload_too_large' }, 413, origin);
      }
      payload = JSON.parse(raw);
    } catch (e) {
      return jsonResponse({ error: 'invalid_json' }, 400, origin);
    }

    const { messages, system, model, max_tokens } = payload || {};
    if (!Array.isArray(messages) || !messages.length) {
      return jsonResponse({ error: 'missing_messages' }, 400, origin);
    }

    if (!env.ANTHROPIC_API_KEY) {
      return jsonResponse({ error: 'server_misconfigured', detail: 'ANTHROPIC_API_KEY secret not set on the worker' }, 500, origin);
    }

    const anthropicReq = {
      model: model || 'claude-haiku-4-5-20251001',
      max_tokens: Math.min(max_tokens || 1024, 4096),
      messages,
    };
    if (system) anthropicReq.system = system;

    const upstream = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': env.ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(anthropicReq),
    });

    const text = await upstream.text();
    return new Response(text, {
      status: upstream.status,
      headers: {
        'Content-Type': 'application/json',
        ...corsHeaders(origin),
      },
    });
  },
};
