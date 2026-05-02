// ================== 工具函数 ==================

function generateShortCode() {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const bytes = new Uint8Array(6);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => chars[b % chars.length]).join('');
}

async function sign(data, secret) {
  if (!secret) throw new Error('SIGNING_SECRET 未设置');
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

async function createToken(code, secret, maxAge = 3600) {
  const expiry = Math.floor(Date.now() / 1000) + maxAge;
  const data = `${code}.${expiry}`;
  const sig = await sign(data, secret);
  return `${code}.${expiry}.${sig}`;
}

async function verifyToken(token, secret) {
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [code, expiryStr, sig] = parts;
  const expiry = parseInt(expiryStr);
  if (Date.now() / 1000 > expiry) return null;
  const expectedSig = await sign(`${code}.${expiry}`, secret);
  if (sig.length !== expectedSig.length) return null;
  let valid = true;
  for (let i = 0; i < sig.length; i++) {
    if (sig[i] !== expectedSig[i]) valid = false;
  }
  return valid ? code : null;
}

async function hashPassword(password) {
  const salt = crypto.randomUUID();
  const encoder = new TextEncoder();
  const data = encoder.encode(salt + password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashHex = Array.from(new Uint8Array(hashBuffer), b => b.toString(16).padStart(2, '0')).join('');
  return `${salt}:${hashHex}`;
}

async function verifyPassword(password, stored) {
  if (!stored) return false;
  const [salt, hashHex] = stored.split(':');
  const encoder = new TextEncoder();
  const data = encoder.encode(salt + password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const computed = Array.from(new Uint8Array(hashBuffer), b => b.toString(16).padStart(2, '0')).join('');
  return computed === hashHex;
}

function getAllowedDomains(env) {
  const raw = env.ALLOWED_DOMAINS || '';
  return raw.split(',').map(d => d.trim()).filter(Boolean);
}

// ================== 页面模板 ==================

function homePage(allowedDomains, currentHost) {
  const domainsJson = JSON.stringify(allowedDomains);
  const currentHostJson = JSON.stringify(currentHost);
  const html = HTML_HOME.replace('{{DOMAINS_JSON}}', domainsJson)
                        .replace('{{CURRENT_HOST}}', currentHostJson);
  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

function passwordPage(code, error = '') {
  const msg = error ? `<p style="color:red">${error}</p>` : '';
  return new Response(
    HTML_PASSWORD.replace('{{CODE}}', code).replace('{{ERROR}}', msg),
    { headers: { 'Content-Type': 'text/html; charset=utf-8' } }
  );
}

function notFoundPage() {
  return new Response(HTML_404, {
    status: 404,
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

// ================== 路由处理 ==================

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    try {
      if (pathname === '/' && request.method === 'GET') {
        const allowedDomains = getAllowedDomains(env);
        const currentHost = url.host;
        return homePage(allowedDomains, currentHost);
      }

      if (pathname === '/api/domains' && request.method === 'GET') {
        return new Response(JSON.stringify(getAllowedDomains(env)), {
          headers: { 'Content-Type': 'application/json' }
        });
      }

      if (pathname === '/api/shorten' && request.method === 'POST') {
        return await handleShorten(request, env);
      }

      const code = pathname.slice(1);
      if (code && /^[a-zA-Z0-9_-]+$/.test(code)) {
        if (request.method === 'GET') {
          return await handleRedirect(code, request, env);
        }
        if (request.method === 'POST') {
          return await handlePasswordSubmit(code, request, env);
        }
      }
    } catch (e) {
      // 对 API 请求返回 JSON 错误，避免前端解析失败
      if (pathname.startsWith('/api/')) {
        return new Response(JSON.stringify({ error: e.message }), {
          status: 500,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      return new Response('服务器内部错误', { status: 500 });
    }

    return notFoundPage();
  },

  async scheduled(event, env, ctx) {
    await env.DB.prepare(
      `DELETE FROM links WHERE expires_at IS NOT NULL AND expires_at <= datetime('now')`
    ).run();
  }
};

// ================== API 实现 ==================

async function handleShorten(request, env) {
  const body = await request.json().catch(() => null);
  if (!body || !body.url) {
    return new Response(JSON.stringify({ error: 'Missing url' }), { status: 400 });
  }

  let originalUrl;
  try {
    originalUrl = new URL(body.url).href;
  } catch {
    return new Response(JSON.stringify({ error: 'Invalid URL' }), { status: 400 });
  }

  const allowedDomains = getAllowedDomains(env);
  let domain = body.domain || new URL(request.url).host;
  try {
    if (domain.includes('://')) {
      domain = new URL(domain).hostname;
    } else {
      domain = domain.replace(/\/.*$/, '');
    }
  } catch {
    return new Response(JSON.stringify({ error: 'Invalid domain format' }), { status: 400 });
  }

  if (allowedDomains.length > 0 && !allowedDomains.includes(domain)) {
    return new Response(JSON.stringify({ error: `Domain "${domain}" is not allowed` }), { status: 400 });
  }

  const db = env.DB;
  const existing = await db.prepare(
    `SELECT short_code, password_hash, expires_at FROM links 
     WHERE original_url = ? AND domain = ? 
     AND (expires_at IS NULL OR expires_at > datetime('now'))
     LIMIT 1`
  ).bind(originalUrl, domain).first();

  if (existing) {
    const shortUrl = `https://${domain}/${existing.short_code}`;
    return new Response(JSON.stringify({
      short_url: shortUrl,
      code: existing.short_code,
      reused: true
    }), { headers: { 'Content-Type': 'application/json' } });
  }

  let expiresAt = null;
  if (body.expires_at) {
    const date = new Date(body.expires_at);
    if (isNaN(date.getTime())) {
      return new Response(JSON.stringify({ error: 'Invalid expires_at' }), { status: 400 });
    }
    expiresAt = date.toISOString();
  }

  let passwordHash = null;
  if (body.password && body.password.trim()) {
    passwordHash = await hashPassword(body.password.trim());
  }

  let shortCode;
  for (let attempt = 0; attempt < 5; attempt++) {
    shortCode = generateShortCode();
    try {
      await db.prepare(
        `INSERT INTO links (short_code, original_url, password_hash, expires_at, domain) VALUES (?, ?, ?, ?, ?)`
      ).bind(shortCode, originalUrl, passwordHash, expiresAt, domain).run();
      break;
    } catch (e) {
      if (attempt === 4) {
        return new Response(JSON.stringify({ error: '生成短码失败，请重试' }), { status: 500 });
      }
    }
  }

  const shortUrl = `https://${domain}/${shortCode}`;
  return new Response(JSON.stringify({
    short_url: shortUrl,
    code: shortCode,
    reused: false
  }), { headers: { 'Content-Type': 'application/json' } });
}

async function handleRedirect(code, request, env) {
  const db = env.DB;
  const row = await db.prepare(
    `SELECT original_url, password_hash, expires_at FROM links WHERE short_code = ?`
  ).bind(code).first();

  if (!row) return notFoundPage();

  if (row.expires_at && new Date(row.expires_at) <= new Date()) {
    return new Response('Link has expired', { status: 410 });
  }

  if (!row.password_hash) {
    return Response.redirect(row.original_url, 302);
  }

  const cookieHeader = request.headers.get('Cookie') || '';
  const cookies = cookieHeader.split(';').reduce((acc, c) => {
    const [k, ...v] = c.trim().split('=');
    if (k) acc[k] = v.join('=');
    return acc;
  }, {});

  const token = cookies.pw_token;
  if (token) {
    const validCode = await verifyToken(token, env.SIGNING_SECRET);
    if (validCode === code) {
      return Response.redirect(row.original_url, 302);
    }
  }

  return passwordPage(code);
}

async function handlePasswordSubmit(code, request, env) {
  const db = env.DB;
  const row = await db.prepare(
    `SELECT original_url, password_hash FROM links WHERE short_code = ?`
  ).bind(code).first();

  if (!row || !row.password_hash) return notFoundPage();

  let password;
  const contentType = request.headers.get('Content-Type') || '';
  if (contentType.includes('application/x-www-form-urlencoded')) {
    const formData = await request.formData();
    password = formData.get('password');
  } else if (contentType.includes('application/json')) {
    const json = await request.json().catch(() => null);
    password = json?.password;
  } else {
    password = (await request.text()).trim();
  }

  if (!password || !(await verifyPassword(password, row.password_hash))) {
    return passwordPage(code, '密码错误，请重试');
  }

  const token = await createToken(code, env.SIGNING_SECRET);
  return new Response(null, {
    status: 302,
    headers: {
      'Location': row.original_url,
      'Set-Cookie': `pw_token=${token}; Path=/${code}; HttpOnly; Secure; SameSite=Lax; Max-Age=3600`
    }
  });
}

// ================== 内嵌 HTML ==================

const HTML_HOME = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>短链接生成器</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, -apple-system, sans-serif; background: #f5f7fa; display: flex; justify-content: center; align-items: center; min-height: 100vh; position: relative; }
    .card { background: white; border-radius: 16px; padding: 40px; width: 90%; max-width: 500px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }
    h1 { margin-bottom: 24px; color: #1a1a2e; text-align: center; }
    label { display: block; margin-bottom: 8px; font-weight: 600; color: #333; }
    input, select { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 8px; font-size: 16px; margin-bottom: 20px; }
    .row { display: flex; gap: 12px; }
    .row > div { flex: 1; }
    button { width: 100%; padding: 14px; background: #4361ee; color: white; border: none; border-radius: 8px; font-size: 18px; cursor: pointer; transition: background 0.2s; }
    button:hover { background: #3a56d4; }
    #result { margin-top: 24px; display: none; }
    #result input { background: #f0f0f0; }
    #copyBtn { margin-top: 8px; }
    .info { color: #2e7d32; margin-bottom: 12px; display: none; font-weight: 500; }
    .error { color: #d32f2f; margin-bottom: 16px; display: none; }

    /* ---- 悬浮 GitHub 按钮 ---- */
    .github-float {
      position: fixed;
      bottom: 24px;
      right: 24px;
      width: 56px;
      height: 56px;
      background: #24292e;
      color: white;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      text-decoration: none;
      transition: transform 0.2s, box-shadow 0.2s;
      z-index: 999;
    }
    .github-float:hover {
      transform: scale(1.1);
      box-shadow: 0 6px 16px rgba(0,0,0,0.4);
    }
    .github-float svg {
      width: 28px;
      height: 28px;
      fill: white;
    }
  </style>
</head>
<body>
  <div class="card">
    <h1>🔗 短链接生成器</h1>
    <div class="error" id="error"></div>
    <div class="info" id="info"></div>

    <label for="domain">短链接域名</label>
    <select id="domain"></select>

    <label for="url">目标网址</label>
    <input type="url" id="url" placeholder="https://example.com/very/long/url" required>

    <label for="expiry">有效期</label>
    <div class="row">
      <select id="expiry" style="flex:2">
        <option value="">永久有效</option>
        <option value="1">1 天</option>
        <option value="7">7 天</option>
        <option value="30">30 天</option>
        <option value="custom">自定义日期</option>
      </select>
      <input type="date" id="customDate" style="flex:1; display:none" />
    </div>

    <label for="password">访问密码 (可选)</label>
    <input type="text" id="password" placeholder="留空则不设密码">

    <button id="generateBtn">生成短链接</button>

    <div id="result">
      <label>你的短链接</label>
      <input type="text" id="shortUrl" readonly>
      <button id="copyBtn">复制链接</button>
    </div>
  </div>

  <!-- 悬浮 GitHub 按钮 -->
  <a href="https://github.com/2DOG-G/shorturl_cloudflare" target="_blank" class="github-float" title="查看源码">
    <svg viewBox="0 0 16 16" aria-hidden="true">
      <path d="M8 0C3.58 0 0 3.58 0 8a8 8 0 005.47 7.59c.4.07.55-.17.55-.38
               0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13
               -.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87
               2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95
               0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82
               a7.64 7.64 0 014 0c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12
               .51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54
               1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z"/>
    </svg>
  </a>

  <script>
    const ALLOWED_DOMAINS = {{DOMAINS_JSON}};
    const CURRENT_HOST = {{CURRENT_HOST}};

    const domainSelect = document.getElementById('domain');
    if (ALLOWED_DOMAINS.length > 0) {
      ALLOWED_DOMAINS.forEach(domain => {
        const option = document.createElement('option');
        option.value = domain;
        option.textContent = 'https://' + domain;
        if (domain === CURRENT_HOST) option.selected = true;
        domainSelect.appendChild(option);
      });
    } else {
      const option = document.createElement('option');
      option.value = CURRENT_HOST;
      option.textContent = 'https://' + CURRENT_HOST;
      domainSelect.appendChild(option);
    }

    const expirySelect = document.getElementById('expiry');
    const customDateInput = document.getElementById('customDate');
    expirySelect.addEventListener('change', () => {
      customDateInput.style.display = expirySelect.value === 'custom' ? 'block' : 'none';
    });

    document.getElementById('generateBtn').addEventListener('click', async () => {
      const domain = document.getElementById('domain').value;
      const url = document.getElementById('url').value.trim();
      const password = document.getElementById('password').value;
      const expires = expirySelect.value;
      const errorDiv = document.getElementById('error');
      const infoDiv = document.getElementById('info');
      const resultDiv = document.getElementById('result');
      errorDiv.style.display = 'none';
      infoDiv.style.display = 'none';
      resultDiv.style.display = 'none';

      if (!url) {
        errorDiv.textContent = '请输入目标网址';
        errorDiv.style.display = 'block';
        return;
      }

      let expires_at = null;
      if (expires === 'custom') {
        if (!customDateInput.value) {
          errorDiv.textContent = '请选择自定义日期';
          errorDiv.style.display = 'block';
          return;
        }
        expires_at = new Date(customDateInput.value + 'T23:59:59').toISOString();
      } else if (expires) {
        const days = parseInt(expires);
        expires_at = new Date(Date.now() + days * 86400000).toISOString();
      }

      try {
        const res = await fetch('/api/shorten', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url, domain, expires_at, password: password || undefined })
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || '请求失败');

        document.getElementById('shortUrl').value = data.short_url;
        resultDiv.style.display = 'block';

        if (data.reused) {
          infoDiv.textContent = '✓ 检测到已有未过期短链，已复用';
          infoDiv.style.display = 'block';
        }
      } catch (e) {
        errorDiv.textContent = e.message;
        errorDiv.style.display = 'block';
      }
    });

    document.getElementById('copyBtn').addEventListener('click', () => {
      const input = document.getElementById('shortUrl');
      input.select();
      document.execCommand('copy');
      alert('已复制');
    });
  </script>
</body>
</html>`;

const HTML_PASSWORD = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>需要密码</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: system-ui, sans-serif; background: #f5f7fa; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
    .card { background: white; border-radius: 16px; padding: 40px; width: 90%; max-width: 400px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); text-align: center; }
    h2 { margin-bottom: 20px; }
    input { width: 100%; padding: 12px; border: 1px solid #ddd; border-radius: 8px; font-size: 16px; margin-bottom: 16px; }
    button { width: 100%; padding: 12px; background: #4361ee; color: white; border: none; border-radius: 8px; font-size: 16px; cursor: pointer; }
    button:hover { background: #3a56d4; }
    .error { color: #d32f2f; margin-bottom: 12px; }
  </style>
</head>
<body>
  <div class="card">
    <h2>🔒 此链接需要密码</h2>
    {{ERROR}}
    <form method="post" action="/{{CODE}}">
      <input type="password" name="password" placeholder="输入访问密码" required />
      <button type="submit">验证</button>
    </form>
  </div>
</body>
</html>`;

const HTML_404 = `<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>404</title></head>
<body style="text-align:center; padding-top:100px; font-family:sans-serif;">
  <h1>404 - 链接不存在</h1>
  <a href="/">返回首页</a>
</body>
</html>`;
