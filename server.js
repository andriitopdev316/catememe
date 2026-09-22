const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const net = require('net');

const port = Number(process.env.PORT || 10000);
const root = path.join(__dirname, 'cate.meme');
const dataFile = path.join(__dirname, 'visitors.json');
const invitesFile = path.join(__dirname, 'invites.json');
const adminPassword = process.env.ADMIN_PASSWORD || 'admin';
const sessions = new Set();
const contentTypes = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon'
};

function readVisitors() {
  try { return JSON.parse(fs.readFileSync(dataFile, 'utf8')); } catch (_) { return []; }
}
function writeVisitors(visitors) {
  fs.writeFileSync(dataFile, JSON.stringify(visitors, null, 2));
}
function readInvites() {
  try { return JSON.parse(fs.readFileSync(invitesFile, 'utf8')); } catch (_) { return []; }
}
function writeInvites(invites) {
  fs.writeFileSync(invitesFile, JSON.stringify(invites, null, 2));
}
function json(response, status, value) {
  const body = JSON.stringify(value);
  response.writeHead(status, {'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store'});
  response.end(body);
}
function body(request) {
  return new Promise((resolve, reject) => {
    let value = '';
    request.on('data', chunk => { value += chunk; if (value.length > 10000) request.destroy(); });
    request.on('end', () => { try { resolve(value ? JSON.parse(value) : {}); } catch (_) { reject(new Error('Invalid JSON')); } });
    request.on('error', reject);
  });
}
function authorized(request) {
  const token = (request.headers.authorization || '').replace(/^Bearer\s+/i, '');
  return token && sessions.has(token);
}
function clientIp(request) {
  const candidates = [
    request.headers['cf-connecting-ip'] || '',
    request.headers['true-client-ip'] || '',
    request.headers['fly-client-ip'] || '',
    ...(request.headers['x-forwarded-for'] || '').split(','),
    request.headers['x-real-ip'] || '',
    request.socket.remoteAddress || ''
  ].map(value => value.trim()).filter(Boolean);
  for (const candidate of candidates) {
    const mapped = candidate.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
    if (mapped) return mapped[1];
    if (candidate === '::1') return '127.0.0.1';
    if (net.isIP(candidate)) return candidate;
  }
  return 'Unavailable';
}
function lookupIp(ip) {
  const unavailable = {country: 'Unavailable', region: 'Unavailable', city: 'Unavailable', timezone: 'Unavailable', isp: 'Unavailable', asn: 'Unavailable', connectionType: 'Unavailable', vpn: 'VPN check unavailable', vpnActive: null, vpnCheckState: 'unavailable'};
  if (ip === 'Unavailable' || ip === '127.0.0.1') return Promise.resolve(unavailable);
  return new Promise(resolve => {
    const request = https.get(`https://ipwho.is/${encodeURIComponent(ip)}`, {timeout: 4500, headers: {'User-Agent': 'CATECOIN visitor analytics'}}, response => {
      let value = '';
      response.on('data', chunk => { value += chunk; });
      response.on('end', () => {
        try {
          const data = JSON.parse(value);
          if (data.success === false) return resolve(unavailable);
          const connection = data.connection || {};
          const hasSecurityData = data.security && typeof data.security === 'object';
          const security = hasSecurityData ? data.security : {};
          const provider = String(connection.isp || connection.org || '').trim();
          // IPWhois does not label every commercial VPN exit IP. These provider networks
          // are widely used for anonymizing/VPN egress and are therefore flagged too.
          const vpnInfrastructure = /datacamp|datapacket|m247|leaseweb|choopa|vultr/i.test(provider);
          const anonymizer = security.vpn === true || security.proxy === true || security.tor === true ||
            security.relay === true || security.hosting === true || security.anonymous === true || vpnInfrastructure;
          // A known VPN-hosting network is a positive signal even when the provider's
          // optional security payload is temporarily absent from its free response.
          const vpnCheckState = anonymizer ? 'detected' : !hasSecurityData ? 'unavailable' : 'clear';
          resolve({
            country: data.country || 'Unavailable',
            region: data.region || 'Unavailable',
            city: data.city || 'Unavailable',
            timezone: data.timezone?.id || 'Unavailable',
            isp: provider || 'Unavailable',
            asn: connection.asn ? `AS${connection.asn}` : 'Unavailable',
            connectionType: connection.type || (security.mobile ? 'Cellular' : 'Unavailable'),
            vpn: security.vpn ? `VPN ACTIVE${provider ? ` - ${provider}` : ''}` :
              security.proxy ? 'Proxy detected' : security.tor ? 'Tor detected' :
              (security.relay || security.hosting || security.anonymous || vpnInfrastructure) ? 'VPN / anonymizer infrastructure detected' :
              !hasSecurityData ? 'VPN check unavailable' : 'No VPN detected',
            vpnActive: anonymizer ? true : hasSecurityData ? false : null,
            vpnCheckState
          });
        } catch (_) { resolve(unavailable); }
      });
    });
    request.on('error', () => resolve(unavailable));
    request.on('timeout', () => { request.destroy(); resolve(unavailable); });
  });
}
function browser(userAgent) {
  const match = userAgent.match(/Edg\/([\d.]+)/) || userAgent.match(/Chrome\/([\d.]+)/) || userAgent.match(/Firefox\/([\d.]+)/) || userAgent.match(/Version\/([\d.]+).*Safari/);
  const name = userAgent.includes('Edg/') ? 'Edge' : userAgent.includes('Firefox/') ? 'Firefox' : userAgent.includes('Chrome/') ? 'Chrome' : userAgent.includes('Safari/') ? 'Safari' : 'Other';
  return name + (match ? ` ${match[1]}` : '');
}
// User-Agent model identifiers are inconsistent and increasingly redacted by browsers.
// Keep this deliberately small and return the code whenever it is not a known match.
const deviceModels = {
  'STK-L21': 'Huawei Y9 Prime'
};
function androidModel(userAgent) {
  const androidSection = userAgent.match(/Android\s+[\d.]+;\s*([^)]*)\)/i);
  if (!androidSection) return '';
  const value = androidSection[1]
    .replace(/\s+Build\/.*$/i, '')
    .split(';').map(part => part.trim()).filter(Boolean).pop() || '';
  const code = value.match(/[A-Z]{2,}[A-Z0-9-]{2,}/i)?.[0]?.toUpperCase() || '';
  if (!code) return '';
  return deviceModels[code] ? `${deviceModels[code]} (${code})` : code;
}
function device(userAgent) {
  const windows = userAgent.match(/Windows NT ([\d.]+)/);
  const android = userAgent.match(/Android ([\d.]+)/);
  const mac = userAgent.match(/Mac OS X ([\d_]+)/);
  if (windows) return `PC - Windows ${windows[1]}`;
  if (android) {
    const model = androidModel(userAgent);
    return model ? `Mobile - ${model} · Android ${android[1]}` : `Mobile - Android ${android[1]}`;
  }
  if (/iPhone/i.test(userAgent)) return 'Mobile - iPhone';
  if (mac) return `Mac - macOS ${mac[1].replace(/_/g, '.')}`;
  if (/Linux/i.test(userAgent)) return 'PC - Linux';
  return 'Unknown';
}
function clean(value, limit = 160) {
  return String(value == null ? '' : value).replace(/[\u0000-\u001f<>]/g, '').trim().slice(0, limit) || 'Unavailable';
}
function number(value, max = 100000) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 && parsed <= max ? Math.round(parsed) : null;
}
function clientContext(input, request) {
  const screenWidth = number(input.screenWidth), screenHeight = number(input.screenHeight);
  const viewportWidth = number(input.viewportWidth), viewportHeight = number(input.viewportHeight);
  return {
    language: clean(input.language || request.headers['accept-language']?.split(',')[0], 40),
    timezone: clean(input.timezone, 80),
    platform: clean(input.platform, 80),
    screen: screenWidth && screenHeight ? `${screenWidth} × ${screenHeight}` : 'Unavailable',
    viewport: viewportWidth && viewportHeight ? `${viewportWidth} × ${viewportHeight}` : 'Unavailable',
    colorScheme: clean(input.colorScheme, 20),
    touch: input.touch === true ? 'Touch' : input.touch === false ? 'Pointer' : 'Unavailable',
    clientNetwork: clean(input.clientNetwork, 60),
    referrer: clean(input.referrer, 300),
    page: clean(input.page, 180)
  };
}
function inviteCode() {
  return crypto.randomBytes(5).toString('base64url').replace(/[-_]/g, '').slice(0, 7).toUpperCase();
}
function inviteContext(input) {
  const code = String(input.ref || '').trim().toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 20);
  if (!code) return {inviteCode: 'Direct', inviteName: 'Direct visit'};
  const invite = readInvites().find(value => value.code === code);
  return invite ? {inviteCode: invite.code, inviteName: invite.name} : {inviteCode: code, inviteName: 'Unrecognized invite'};
}
function sessionDuration(input, now) {
  const started = new Date(input.sessionStartedAt || '');
  const elapsed = now.getTime() - started.getTime();
  return Number.isFinite(elapsed) && elapsed >= 0 && elapsed <= 12 * 60 * 60 * 1000
    ? Math.floor(elapsed / 1000) : 0;
}
function safePath(urlPath) {
  const requested = urlPath === '/' ? '/index.html' : urlPath;
  const file = path.resolve(root, `.${requested}`);
  return file === root || file.startsWith(root + path.sep) ? file : null;
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  try {
    if (request.method === 'POST' && url.pathname === '/api/visitors') {
      const input = await body(request);
      const identity = String(input.id || crypto.randomUUID()).slice(0, 100);
      const now = new Date().toISOString();
      const currentVisitors = readVisitors();
      const current = currentVisitors.find(visitor => visitor.id === identity);
      const ip = clientIp(request);
      const reusePrevious = current && input.event !== 'visit';
      const network = reusePrevious ? {
        country: current.country, region: current.region, city: current.city,
        timezone: current.geoTimezone, isp: current.isp, asn: current.asn,
        connectionType: current.connectionType, vpn: current.vpn, vpnActive: current.vpnActive, vpnCheckState: current.vpnCheckState
      } : await lookupIp(ip);
      const visitors = readVisitors();
      const previous = visitors.find(visitor => visitor.id === identity);
      const context = clientContext(input, request);
      const invite = previous ? {inviteCode: previous.inviteCode, inviteName: previous.inviteName} : inviteContext(input);
      const record = {
        id: identity, ip,
        country: request.headers['cf-ipcountry'] || request.headers['x-country'] || network.country,
        region: network.region, city: network.city, geoTimezone: network.timezone,
        isp: network.isp, asn: network.asn, connectionType: network.connectionType, vpn: network.vpn, vpnActive: network.vpnActive, vpnCheckState: network.vpnCheckState, vpnCheckVersion: 6,
        browser: browser(request.headers['user-agent'] || ''), device: device(request.headers['user-agent'] || ''),
        userAgent: clean(request.headers['user-agent'], 500), ...context, ...invite,
        firstSeen: previous?.firstSeen || now, lastSeen: now,
        sessionDurationSeconds: sessionDuration(input, new Date(now)),
        visits: (previous?.visits || 0) + (input.event === 'visit' || (!input.event && !previous) ? 1 : 0)
      };
      const index = visitors.findIndex(visitor => visitor.id === identity);
      if (index >= 0) visitors[index] = {...visitors[index], ...record}; else visitors.push(record);
      writeVisitors(visitors);
      return json(response, 200, record);
    }
    if (request.method === 'POST' && url.pathname === '/api/admin/login') {
      const input = await body(request);
      if (input.password !== adminPassword) return json(response, 401, {error: 'Incorrect password'});
      const token = crypto.randomBytes(32).toString('hex');
      sessions.add(token);
      return json(response, 200, {token});
    }
    if (request.method === 'GET' && url.pathname === '/api/invites') {
      if (!authorized(request)) return json(response, 401, {error: 'Unauthorized'});
      return json(response, 200, readInvites());
    }
    if (request.method === 'POST' && url.pathname === '/api/invites') {
      if (!authorized(request)) return json(response, 401, {error: 'Unauthorized'});
      const input = await body(request);
      const name = clean(input.name, 80);
      if (name === 'Unavailable') return json(response, 400, {error: 'A name is required'});
      const invites = readInvites();
      let code;
      do { code = inviteCode(); } while (invites.some(invite => invite.code === code));
      const invite = {name, code, createdAt: new Date().toISOString(), path: `/?ref=${code}`};
      invites.push(invite);
      writeInvites(invites);
      return json(response, 201, invite);
    }
    if (request.method === 'GET' && url.pathname === '/api/visitors') {
      if (!authorized(request)) return json(response, 401, {error: 'Unauthorized'});
      const visitors = readVisitors();
      let changed = false;
      for (const visitor of visitors) {
        if (visitor.ip && visitor.ip !== 'Unavailable' && (!visitor.country || visitor.country === 'Unavailable' || visitor.vpnCheckVersion !== 6)) {
          const network = await lookupIp(visitor.ip);
          Object.assign(visitor, {
            country: network.country, region: network.region, city: network.city,
            geoTimezone: network.timezone, isp: network.isp, asn: network.asn,
            connectionType: network.connectionType, vpn: network.vpn, vpnActive: network.vpnActive, vpnCheckState: network.vpnCheckState, vpnCheckVersion: 6
          });
          changed = true;
        }
      }
      if (changed) writeVisitors(visitors);
      return json(response, 200, visitors);
    }
    if (request.method === 'DELETE' && url.pathname.startsWith('/api/visitors/')) {
      if (!authorized(request)) return json(response, 401, {error: 'Unauthorized'});
      const id = decodeURIComponent(url.pathname.slice('/api/visitors/'.length));
      writeVisitors(readVisitors().filter(visitor => visitor.id !== id));
      return json(response, 200, {ok: true});
    }
    if (request.method !== 'GET' && request.method !== 'HEAD') return json(response, 405, {error: 'Method not allowed'});
    const file = safePath(url.pathname);
    if (!file) return json(response, 403, {error: 'Forbidden'});
    fs.readFile(file, (error, content) => {
      if (error) return response.writeHead(404).end('Not found');
      const type = contentTypes[path.extname(file).toLowerCase()] || 'application/octet-stream';
      response.writeHead(200, {'Content-Type': type, 'X-Content-Type-Options': 'nosniff'});
      response.end(content);
    });
  } catch (error) {
    json(response, 400, {error: error.message || 'Request failed'});
  }
});

server.listen(port, () => console.log(`CATECOIN server listening on ${port}`));
