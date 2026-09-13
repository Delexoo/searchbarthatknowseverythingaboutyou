const http = require('http');
const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');

const PORT = Number(process.env.PORT) || 8080;
const ROOT = __dirname;
const OPENROUTER_URL = 'https://openrouter.ai/api/v1/chat/completions';
const GROQ_URL = 'https://api.groq.com/openai/v1/chat/completions';
const GROQ_MODELS = ['openai/gpt-oss-20b', 'llama-3.3-70b-versatile', 'llama-3.1-8b-instant'];

function loadEnv() {
    const envPath = path.join(ROOT, '.env');
    if (!fs.existsSync(envPath)) return;
    for (const line of fs.readFileSync(envPath, 'utf8').split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;
        const eq = trimmed.indexOf('=');
        if (eq === -1) continue;
        const key = trimmed.slice(0, eq).trim();
        const value = trimmed.slice(eq + 1).trim().replace(/^['"]|['"]$/g, '');
        if (key && process.env[key] == null) process.env[key] = value;
    }
}

loadEnv();

const OPENROUTER_KEY = process.env.OPENROUTER_API_KEY || '';
const GROQ_KEY = process.env.GROQ_API_KEY || '';
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
const HIBP_API_KEY = process.env.HIBP_API_KEY || '';
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY || '';
const IPINFO_TOKEN = process.env.IPINFO_TOKEN || '';
const OPENROUTER_MODELS = [
    process.env.OPENROUTER_MODEL,
    'openai/gpt-4o-mini',
    'google/gemini-2.0-flash-001',
    'meta-llama/llama-3.3-70b-instruct'
].filter(Boolean);

const MIME = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif': 'image/gif',
    '.webp': 'image/webp',
    '.ico': 'image/x-icon',
    '.txt': 'text/plain; charset=utf-8'
};

const BLOCKED = new Set(['server.js', 'app.py', '.env', '.gitignore', 'requirements.txt']);

const SYSTEM_PROMPT = `You are a research assistant for open-source intelligence (OSINT) using only public information and public lookup tools.

Help the user understand what a phone number, email, username, IP, domain, or similar identifier looks like, and point them to legitimate public sources (WHOIS, Have I Been Pwned, search engines, social directories, breach-check sites, geolocation lookups).

Be concise, practical, and structured. Use markdown. Do not provide instructions for unauthorized access, password attacks, credential stuffing, phishing, or bypassing security.`;

function sendJson(res, status, payload) {
    res.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        'Access-Control-Allow-Origin': '*'
    });
    res.end(JSON.stringify(payload));
}

function setCors(res) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
}

function readBody(req) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        req.on('data', (chunk) => chunks.push(chunk));
        req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        req.on('error', reject);
    });
}

function detectInputType(inputText) {
    const value = String(inputText || '').trim();
    const compact = value.replace(/[\s().-]/g, '');
    if (/^[\+]?\d{7,15}$/.test(compact)) return 'phone';
    if (/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(value)) return 'email';
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(value)) return 'ip';
    if (/\./.test(value) && (value.toLowerCase().includes('http') || value.toLowerCase().includes('www') || value.split('.').length >= 2)) {
        return 'domain';
    }
    if (/^[a-zA-Z0-9_]{3,20}$/.test(value)) return 'username';
    return 'general';
}

function getOsintOptions(inputType) {
    const options = {
        phone: [
            { name: 'Reverse Phone Lookup', type: 'phone_lookup' },
            { name: 'Social Media Search', type: 'phone_social' },
            { name: 'Data Breach Check', type: 'phone_breach' },
            { name: 'Carrier Lookup', type: 'phone_carrier' },
            { name: 'Location Tracking', type: 'phone_location' }
        ],
        email: [
            { name: 'Email Breach Check', type: 'email_breach' },
            { name: 'Social Media Search', type: 'email_social' },
            { name: 'Domain Analysis', type: 'email_domain' },
            { name: 'Gravatar Lookup', type: 'email_gravatar' },
            { name: 'Pastebin Search', type: 'email_pastebin' }
        ],
        ip: [
            { name: 'IP Geolocation', type: 'ip_geo' },
            { name: 'Whois Lookup', type: 'ip_whois' },
            { name: 'Port Scanner', type: 'ip_ports' },
            { name: 'Threat Intelligence', type: 'ip_threat' },
            { name: 'DNS Records', type: 'ip_dns' }
        ],
        domain: [
            { name: 'Whois Lookup', type: 'domain_whois' },
            { name: 'Subdomain Discovery', type: 'domain_subdomains' },
            { name: 'SSL Certificate', type: 'domain_ssl' },
            { name: 'DNS Records', type: 'domain_dns' },
            { name: 'Historical Data', type: 'domain_history' }
        ],
        username: [
            { name: 'Social Media Search', type: 'username_social' },
            { name: 'GitHub Search', type: 'username_github' },
            { name: 'Pastebin Search', type: 'username_pastebin' },
            { name: 'Forum Search', type: 'username_forums' },
            { name: 'Image Search', type: 'username_images' }
        ],
        general: [
            { name: 'General Search', type: 'general_search' },
            { name: 'Social Media', type: 'general_social' },
            { name: 'News Search', type: 'general_news' },
            { name: 'Image Search', type: 'general_images' }
        ]
    };
    return options[inputType] || options.general;
}

function getOsintResources(resourceType, inputValue) {
    const cleanValue = String(inputValue || '').replace(/[\s+()-]/g, '');
    const encoded = encodeURIComponent(inputValue || '');
    const domainPart = String(inputValue || '').includes('@') ? String(inputValue).split('@')[1] : inputValue;
    const resources = {
        phone_lookup: [
            { name: 'TrueCaller', url: `https://www.truecaller.com/search/${cleanValue}` },
            { name: 'WhitePages', url: `https://www.whitepages.com/phone/${cleanValue}` },
            { name: 'SpyDialer', url: `https://www.spydialer.com/${cleanValue}` }
        ],
        phone_social: [
            { name: 'Facebook Search', url: `https://www.facebook.com/search/people/?q=${cleanValue}` },
            { name: 'LinkedIn Search', url: `https://www.linkedin.com/search/results/all/?keywords=${cleanValue}` },
            { name: 'Twitter Search', url: `https://twitter.com/search?q=${cleanValue}` }
        ],
        phone_breach: [
            { name: 'Have I Been Pwned', url: 'https://haveibeenpwned.com/' },
            { name: 'DeHashed', url: `https://dehashed.com/search?query=${cleanValue}` }
        ],
        phone_carrier: [
            { name: 'Carrier Lookup', url: `https://www.carrierlookup.com/${cleanValue}` },
            { name: 'FreeCarrierLookup', url: `https://freecarrierlookup.com/${cleanValue}` }
        ],
        phone_location: [
            { name: 'Phone Location', url: `https://www.truepeoplesearch.com/phone/${cleanValue}` },
            { name: 'Area Code Lookup', url: `https://www.allareacodes.com/${cleanValue.slice(0, 3)}` }
        ],
        email_breach: [
            { name: 'Have I Been Pwned', url: `https://haveibeenpwned.com/account/${encoded}` },
            { name: 'DeHashed', url: `https://dehashed.com/search?query=${encoded}` }
        ],
        email_social: [
            { name: 'Facebook Search', url: `https://www.facebook.com/search/people/?q=${encoded}` },
            { name: 'Hunter.io', url: `https://hunter.io/email-verifier/${encoded}` }
        ],
        email_domain: [
            { name: 'Domain Search', url: `https://whois.net/${domainPart}` },
            { name: 'MX Toolbox', url: `https://mxtoolbox.com/SuperTool.aspx?action=mx%3a${domainPart}` }
        ],
        email_gravatar: [
            { name: 'Gravatar', url: `https://en.gravatar.com/${encoded}` }
        ],
        email_pastebin: [
            { name: 'Google Pastebin', url: `https://www.google.com/search?q=site:pastebin.com+${encoded}` }
        ],
        ip_geo: [
            { name: 'IPInfo', url: `https://ipinfo.io/${inputValue}` },
            { name: 'IP Geolocation', url: `https://ipgeolocation.io/lookup/${inputValue}` }
        ],
        ip_whois: [
            { name: 'Whois IP', url: `https://whois.net/ip/${inputValue}` },
            { name: 'ARIN Lookup', url: `https://whois.arin.net/rest/ip/${inputValue}` }
        ],
        ip_ports: [
            { name: 'Shodan', url: `https://www.shodan.io/host/${inputValue}` },
            { name: 'Censys', url: `https://search.censys.io/hosts/${inputValue}` }
        ],
        ip_threat: [
            { name: 'AbuseIPDB', url: `https://www.abuseipdb.com/check/${inputValue}` },
            { name: 'VirusTotal', url: `https://www.virustotal.com/gui/ip-address/${inputValue}` }
        ],
        ip_dns: [
            { name: 'DNS Lookup', url: `https://dnschecker.org/#A/${inputValue}` }
        ],
        domain_whois: [
            { name: 'Whois Lookup', url: `https://whois.net/${inputValue}` },
            { name: 'ICANN Lookup', url: 'https://lookup.icann.org/lookup' }
        ],
        domain_subdomains: [
            { name: 'Crt.sh', url: `https://crt.sh/?q=${inputValue}` }
        ],
        domain_ssl: [
            { name: 'SSL Labs', url: `https://www.ssllabs.com/ssltest/analyze.html?d=${inputValue}` }
        ],
        domain_dns: [
            { name: 'DNS Checker', url: `https://dnschecker.org/#A/${inputValue}` }
        ],
        domain_history: [
            { name: 'Wayback Machine', url: `https://web.archive.org/web/*/${inputValue}` }
        ],
        username_social: [
            { name: 'Namechk', url: `https://namechk.com/${inputValue}` },
            { name: 'KnowEm', url: `https://knowem.com/${inputValue}` }
        ],
        username_github: [
            { name: 'GitHub Search', url: `https://github.com/search?q=${encoded}` },
            { name: 'GitHub Profile', url: `https://github.com/${inputValue}` }
        ],
        username_pastebin: [
            { name: 'Google Pastebin', url: `https://www.google.com/search?q=site:pastebin.com+${encoded}` }
        ],
        username_forums: [
            { name: 'Reddit Search', url: `https://www.reddit.com/search/?q=${encoded}` }
        ],
        username_images: [
            { name: 'Google Images', url: `https://www.google.com/search?tbm=isch&q=${encoded}` }
        ],
        general_search: [
            { name: 'Google Search', url: `https://www.google.com/search?q=${encoded}` },
            { name: 'DuckDuckGo', url: `https://duckduckgo.com/?q=${encoded}` }
        ],
        general_social: [
            { name: 'Facebook', url: `https://www.facebook.com/search/people/?q=${encoded}` },
            { name: 'Twitter', url: `https://twitter.com/search?q=${encoded}` }
        ],
        general_news: [
            { name: 'Google News', url: `https://news.google.com/search?q=${encoded}` }
        ],
        general_images: [
            { name: 'Google Images', url: `https://www.google.com/search?tbm=isch&q=${encoded}` }
        ]
    };
    return resources[resourceType] || [{ name: 'General Search', url: `https://www.google.com/search?q=${encoded}` }];
}

async function fetchJson(url, headers = {}) {
    const response = await fetch(url, {
        headers: { 'User-Agent': 'SearchBarLocal/1.0', ...headers }
    });
    const data = await response.json().catch(() => ({}));
    return { ok: response.ok, status: response.status, data };
}

async function enrichQuery(message) {
    const value = String(message || '').trim();
    const type = detectInputType(value);
    const parts = [];

    try {
        if (type === 'ip') {
            if (IPINFO_TOKEN) {
                const lookup = await fetchJson(`https://ipinfo.io/${encodeURIComponent(value)}/json`, {
                    Authorization: `Bearer ${IPINFO_TOKEN}`
                });
                if (lookup.ok) parts.push('IP info: ' + JSON.stringify(lookup.data));
            } else {
                const lookup = await fetchJson('https://ipwho.is/' + encodeURIComponent(value));
                if (lookup.ok) parts.push('IP geolocation: ' + JSON.stringify(lookup.data));
            }
            if (VIRUSTOTAL_API_KEY) {
                const vt = await fetchJson(`https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(value)}`, {
                    'x-apikey': VIRUSTOTAL_API_KEY
                });
                if (vt.ok) parts.push('VirusTotal: ' + JSON.stringify(vt.data?.data?.attributes?.last_analysis_stats || vt.data));
            }
        } else if (type === 'domain') {
            const host = value.replace(/^https?:\/\//i, '').split('/')[0];
            const dns = await fetchJson('https://dns.google/resolve?name=' + encodeURIComponent(host) + '&type=A');
            if (dns.ok) parts.push('DNS A: ' + JSON.stringify(dns.data));
        } else if (type === 'username') {
            const headers = GITHUB_TOKEN ? { Authorization: `Bearer ${GITHUB_TOKEN}` } : {};
            const github = await fetchJson('https://api.github.com/users/' + encodeURIComponent(value), headers);
            if (github.ok) parts.push('GitHub profile: ' + JSON.stringify(github.data));
            else if (github.status === 404) parts.push('GitHub: no user named ' + value);
        } else if (type === 'email') {
            const domain = value.split('@')[1];
            if (domain) {
                const mx = await fetchJson('https://dns.google/resolve?name=' + encodeURIComponent(domain) + '&type=MX');
                if (mx.ok) parts.push('Email domain MX: ' + JSON.stringify(mx.data));
            }
            if (HIBP_API_KEY) {
                const hibp = await fetchJson('https://haveibeenpwned.com/api/v3/breachedaccount/' + encodeURIComponent(value) + '?truncateResponse=true', {
                    'hibp-api-key': HIBP_API_KEY
                });
                if (hibp.status === 404) parts.push('HIBP: no breaches found for this email');
                else if (hibp.ok) parts.push('HIBP breaches: ' + JSON.stringify(hibp.data));
            }
        }
    } catch (error) {
        console.error('Enrichment failed:', error.message);
    }

    return parts.join('\n');
}

async function callChatApi(url, apiKey, models, messages, extraHeaders = {}) {
    let lastError = null;
    for (const model of models) {
        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${apiKey}`,
                    'User-Agent': 'SearchBarLocal/1.0',
                    ...extraHeaders
                },
                body: JSON.stringify({ model, messages, temperature: 0.7 })
            });
            const data = await response.json();
            if (!response.ok) {
                lastError = new Error(data.error?.message || `HTTP ${response.status}`);
                continue;
            }
            const text = data.choices?.[0]?.message?.content;
            if (text) return text;
            lastError = new Error('Empty model response');
        } catch (error) {
            lastError = error;
        }
    }
    throw lastError || new Error('All models failed');
}

async function callAI(messages) {
    if (OPENROUTER_KEY) {
        try {
            return await callChatApi(OPENROUTER_URL, OPENROUTER_KEY, OPENROUTER_MODELS, messages, {
                'HTTP-Referer': 'http://localhost:8080',
                'X-OpenRouter-Title': 'searchbarthatknowseverythingaboutyou'
            });
        } catch (error) {
            if (!GROQ_KEY) throw error;
            console.error('OpenRouter failed, trying Groq:', error.message);
        }
    }
    if (GROQ_KEY) {
        return callChatApi(GROQ_URL, GROQ_KEY, GROQ_MODELS, messages);
    }
    throw new Error('No AI key configured. Set OPENROUTER_API_KEY in .env');
}

function serveStatic(req, res, urlPath) {
    let filePath = urlPath === '/' ? '/index.html' : urlPath;
    filePath = decodeURIComponent(filePath.split('?')[0]);
    const baseName = path.basename(filePath);
    if (BLOCKED.has(baseName)) {
        res.writeHead(404);
        res.end('Not found');
        return;
    }
    const abs = path.normalize(path.join(ROOT, filePath));
    if (!abs.startsWith(ROOT)) {
        res.writeHead(403);
        res.end('Forbidden');
        return;
    }
    fs.readFile(abs, (err, data) => {
        if (err) {
            res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end('Not found');
            return;
        }
        const ext = path.extname(abs).toLowerCase();
        res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
        res.end(data);
    });
}

const server = http.createServer(async (req, res) => {
    setCors(res);
    const urlPath = req.url || '/';

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    try {
        if (req.method === 'POST' && urlPath.split('?')[0] === '/log') {
            sendJson(res, 200, { status: 'ok' });
            return;
        }

        if (req.method === 'POST' && urlPath.split('?')[0] === '/chat') {
            let body;
            try {
                body = JSON.parse((await readBody(req)) || '{}');
            } catch {
                sendJson(res, 400, { error: 'Invalid JSON body' });
                return;
            }
            const message = String(body.message || '').trim();
            if (!message) {
                sendJson(res, 400, { error: 'No message provided' });
                return;
            }
            const context = await enrichQuery(message);
            const userContent = context
                ? `Public lookup data:\n${context}\n\nUser query: ${message}`
                : message;
            const reply = await callAI([
                { role: 'system', content: SYSTEM_PROMPT },
                { role: 'user', content: userContent }
            ]);
            sendJson(res, 200, { type: 'ai_response', response: reply });
            return;
        }

        if (req.method === 'POST' && urlPath.split('?')[0] === '/summarize') {
            const body = JSON.parse((await readBody(req)) || '{}');
            const conversation = String(body.conversation || '').trim();
            const instruction = String(body.instruction || 'Summarize this conversation in 2 brief sentences.');
            if (!conversation) {
                sendJson(res, 400, { error: 'No conversation provided' });
                return;
            }
            const summary = await callAI([
                { role: 'system', content: 'You summarize conversations briefly and clearly.' },
                { role: 'user', content: `${instruction}\n\nConversation:\n${conversation}` }
            ]);
            sendJson(res, 200, { summary, response: summary });
            return;
        }

        if (req.method === 'POST' && urlPath.split('?')[0] === '/osint-resources') {
            const body = JSON.parse((await readBody(req)) || '{}');
            const resourceType = body.type || '';
            const inputValue = body.value || '';
            if (!resourceType || !inputValue) {
                sendJson(res, 400, { error: 'Missing parameters' });
                return;
            }
            sendJson(res, 200, {
                type: 'osint_resources',
                resources: getOsintResources(resourceType, inputValue)
            });
            return;
        }

        if (req.method === 'GET' && urlPath.split('?')[0] === '/osint-options') {
            const query = new URL(req.url, `http://127.0.0.1:${PORT}`).searchParams;
            const value = query.get('value') || '';
            const inputType = detectInputType(value);
            sendJson(res, 200, {
                input_type: inputType,
                options: getOsintOptions(inputType)
            });
            return;
        }

        if (req.method === 'GET') {
            serveStatic(req, res, urlPath.split('?')[0]);
            return;
        }

        res.writeHead(405);
        res.end('Method not allowed');
    } catch (error) {
        console.error(error);
        sendJson(res, 500, { error: error.message || 'Server error' });
    }
});

server.listen(PORT, () => {
    const url = `http://localhost:${PORT}`;
    console.log(`Search bar running at ${url}`);
    console.log('Press Ctrl+C to stop.');
    if (process.platform === 'win32' && !process.env.CI) {
        exec(`cmd /c start "" "${url}"`);
    }
});
