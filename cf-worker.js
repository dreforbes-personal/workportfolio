/**
 * Ask-About-Dre — Cloudflare Worker proxy.
 *
 * Two routes:
 *   POST /        → proxy to Anthropic Messages API (for the chat)
 *   POST /auth    → verify a settings-page password (returns {ok:true|false})
 *                   So the password lives as a Cloudflare secret, not in HTML source.
 *
 * SECRETS to set in Workers → Settings → Variables and Secrets:
 *   ANTHROPIC_API_KEY   (required) — sk-ant-... from console.anthropic.com
 *   SETTINGS_PASSWORD   (optional) — gates /settings.html on the showcase
 *   ASK_TOKEN           (optional) — extra shared-secret if you ever want the chat
 *                                    requests to require a token too
 *
 * Other rules:
 *   - Only requests from ALLOWED_ORIGINS get through (CORS + origin check)
 *   - Per-IP rate limit (in-memory, best-effort)
 *   - Max body size 32 KB
 */

const ALLOWED_ORIGINS = [
  'https://dreforbes-personal.github.io',
  // add http://localhost:3000 etc. here for local testing if needed
];

const MAX_BODY_BYTES = 32 * 1024;          // ~32 KB per request
const RATE_LIMIT_MAX = 30;                  // requests per window
const RATE_LIMIT_WINDOW_MS = 60 * 1000;     // 1 minute

const ipBuckets = new Map();

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

// Constant-time string compare to defeat timing oracles on password check
function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

async function readJson(request, origin) {
  const raw = await request.text();
  if (raw.length > MAX_BODY_BYTES) {
    throw jsonResponse({ error: 'payload_too_large' }, 413, origin);
  }
  try {
    return JSON.parse(raw);
  } catch (e) {
    throw jsonResponse({ error: 'invalid_json' }, 400, origin);
  }
}

async function handleAuth(request, env, origin) {
  if (!env.SETTINGS_PASSWORD) {
    return jsonResponse({ error: 'server_misconfigured', detail: 'SETTINGS_PASSWORD secret not set on the worker' }, 500, origin);
  }
  let payload;
  try { payload = await readJson(request, origin); }
  catch (resp) { return resp; }
  const provided = (payload && typeof payload.password === 'string') ? payload.password : '';
  const ok = safeEqual(provided, env.SETTINGS_PASSWORD);
  // Add a tiny artificial delay so brute-force is even less attractive
  await new Promise(r => setTimeout(r, 250));
  return jsonResponse({ ok }, ok ? 200 : 401, origin);
}

async function handleChat(request, env, origin) {
  if (env.ASK_TOKEN) {
    const provided = request.headers.get('X-Ask-Token');
    if (provided !== env.ASK_TOKEN) {
      return jsonResponse({ error: 'unauthorized' }, 401, origin);
    }
  }
  if (!env.ANTHROPIC_API_KEY) {
    return jsonResponse({ error: 'server_misconfigured', detail: 'ANTHROPIC_API_KEY secret not set on the worker' }, 500, origin);
  }
  let payload;
  try { payload = await readJson(request, origin); }
  catch (resp) { return resp; }
  const { messages, system, model, max_tokens } = payload || {};
  if (!Array.isArray(messages) || !messages.length) {
    return jsonResponse({ error: 'missing_messages' }, 400, origin);
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

    const url = new URL(request.url);
    if (url.pathname === '/auth') {
      return handleAuth(request, env, origin);
    }
    return handleChat(request, env, origin);
  },
};
