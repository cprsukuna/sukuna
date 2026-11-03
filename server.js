"use strict";
const express = require('express');
const session = require('express-session');
const multer  = require('multer');
const path = require('path');
const fs   = require('fs');
const os   = require('os');
const crypto = require('crypto');
const { spawn, execSync } = require('child_process');

const app = express();
const PORT   = process.env.PORT || 8000;
const USER   = process.env.SUKUNA_USER || 'hardik2321';
const PASS   = process.env.SUKUNA_PASS || 'Hardik@2321';
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

const HOST_DIR = path.join(__dirname, 'hosted');
const TMP_DIR  = path.join(__dirname, '.tmp');
const MAX_STORAGE = 1024 * 1024 * 1024;

[HOST_DIR, TMP_DIR].forEach(d => { if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true }); });

app.set('trust proxy', 1);
app.use(session({
  secret: SECRET, resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 2*60*60*1000 }
}));
app.use(express.json({ limit: '16mb' }));
app.use(express.static(path.join(__dirname, 'public')));

/* ─────────── helpers ─────────── */
const human = n => { const u=['B','KB','MB','GB','TB']; let i=0; while(n>=1024&&i<u.length-1){n/=1024;i++;} return n.toFixed(1)+' '+u[i]; };
const dirSize = d => { let t=0; try{ for(const n of fs.readdirSync(d)){ const fp=path.join(d,n); const st=fs.statSync(fp); t+=st.isDirectory()?dirSize(fp):st.size; } }catch(e){} return t; };
const listFiles = () => fs.readdirSync(HOST_DIR).filter(f => { try { return fs.statSync(path.join(HOST_DIR,f)).isFile(); } catch { return false; } });
const auth = (req,res,next) => req.session?.auth ? next() : res.status(401).json({ ok:false });
const newRunId = () => crypto.randomBytes(8).toString('hex');

/* ─────────── process registry ─────────── */
const processes = new Map(); // runId -> { proc, file, cmd, startTime, stdout, stderr, exitCode, done, listeners }

/* ─────────── login ─────────── */
const attempts = new Map();
app.post('/api/login', (req,res) => {
  const ip = req.ip || 'x';
  const rec = attempts.get(ip) || { n:0, until:0 };
  if (rec.until > Date.now()) return res.status(429).json({ ok:false, msg:`locked ${Math.ceil((rec.until-Date.now())/1000)}s` });
  const { user='', pass='' } = req.body || {};
  const eq = (a,b) => a.length===b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  if (eq(String(user), USER) && eq(String(pass), PASS)) {
    req.session.auth = true;
    attempts.delete(ip);
    return res.json({ ok:true });
  }
  rec.n++;
  if (rec.n >= 5) { rec.until = Date.now() + 60_000; rec.n = 0; }
  attempts.set(ip, rec);
  res.status(401).json({ ok:false, msg:`invalid · ${5-rec.n} left` });
});
app.post('/api/logout', (req,res) => { req.session.destroy(); res.json({ ok:true }); });
app.get('/api/me', (req,res) => res.json({ ok: !!req.session?.auth }));

/* ─────────── stats ─────────── */
let lastCpu = os.cpus().map(c => c.times);
const cpuPct = () => {
  const now = os.cpus().map(c => c.times);
  let idle=0, total=0;
  for (let i=0;i<now.length;i++) {
    const a=lastCpu[i], b=now[i];
    idle += b.idle-a.idle;
    total += (b.user+b.nice+b.sys+b.idle+b.irq) - (a.user+a.nice+a.sys+a.idle+a.irq);
  }
  lastCpu = now;
  return total ? Math.round((1-idle/total)*1000)/10 : 0;
};
const ver = c => { try { return execSync(c, { timeout:3000 }).toString().trim(); } catch { return ''; } };

app.get('/api/stats', auth, (req,res) => {
  const total = os.totalmem()/1024**3;
  const free  = os.freemem()/1024**3;
  const used  = Math.min(4, total-free);
  const sto   = dirSize(HOST_DIR);
  const f     = listFiles();
  const running = [...processes.values()].filter(r => !r.done).length;
  res.json({
    ok:true,
    cpu: cpuPct(),
    ram: { used_gb:+used.toFixed(2), total_gb:4 },
    storage: { used_h:human(sto), pct:+(sto/MAX_STORAGE*100).toFixed(1) },
    uptime: Math.floor(process.uptime()),
    node: process.version,
    python: (ver('python3 --version') || ver('python --version')).replace('Python ',''),
    platform: `${os.platform()} ${os.release()}`,
    hosted: f[0] || null,
    running,
  });
});

/* ─────────── python scan ─────────── */
app.get('/api/python/versions', auth, (req,res) => {
  const seen = new Set(), out = [];
  for (const n of ['python3','python','python3.13','python3.12','python3.11','python3.10','python3.9','python3.8','python2']) {
    try {
      const p = execSync(`command -v ${n}`, { timeout:1500 }).toString().trim();
      if (!p || seen.has(p)) continue;
      seen.add(p);
      const v = execSync(`${p} --version 2>&1`, { timeout:2000 }).toString().trim();
      out.push({ path:p, version:v, active:n==='python3' });
    } catch {}
  }
  res.json({ ok:true, versions:out });
});

/* ─────────── files ─────────── */
const upload = multer({ dest: TMP_DIR, limits: { fileSize: MAX_STORAGE } });

app.get('/api/files', auth, (req,res) => {
  res.json({
    ok:true,
    files: listFiles().map(f => {
      const st = fs.statSync(path.join(HOST_DIR, f));
      const running = [...processes.entries()].find(([id,r]) => r.file===f && !r.done);
      return { name:f, size:st.size, mtime:st.mtimeMs, runId: running ? running[0] : null };
    }),
    used_h: human(dirSize(HOST_DIR)),
    limit_h: human(MAX_STORAGE),
  });
});

app.post('/api/upload', auth, upload.single('file'), (req,res) => {
  if (!req.file) return res.status(400).json({ ok:false, msg:'no file' });
  const safe = path.basename(req.file.originalname).replace(/[^a-zA-Z0-9._-]/g,'_') || 'index.html';
  const dest = path.join(HOST_DIR, safe);
  try { if (fs.existsSync(dest)) fs.unlinkSync(dest); } catch(e){}
  fs.renameSync(req.file.path, dest);
  res.json({ ok:true, msg:`uploaded ${safe}`, file: safe });
});

app.post('/api/delete', auth, (req,res) => {
  const { file } = req.body || {};
  if (!file) return res.json({ ok:false, msg:'no file' });
  // stop if running
  for (const [id, r] of processes) {
    if (r.file === file && !r.done) {
      try { killTree(r.proc.pid); } catch(e){}
    }
  }
  const safe = path.basename(file);
  const full = path.join(HOST_DIR, safe);
  if (fs.existsSync(full)) fs.unlinkSync(full);
  res.json({ ok:true, msg:`deleted ${safe}` });
});

app.get('/site', (req,res) => {
  const f = listFiles();
  const html = f.find(x => /\.html?$/i.test(x));
  if (!html) {
    if (!f.length) return res.status(404).send('<h1>No file hosted</h1>');
    return res.sendFile(path.join(HOST_DIR, f[0]));
  }
  res.sendFile(path.join(HOST_DIR, html));
});

/* ─────────── file content (view / edit) ─────────── */
app.get('/api/file/:name', auth, (req,res) => {
  const safe = path.basename(req.params.name);
  const full = path.join(HOST_DIR, safe);
  if (!fs.existsSync(full)) return res.json({ ok:false, msg:'not found' });
  try {
    const st = fs.statSync(full);
    if (st.size > 1024 * 512) return res.json({ ok:false, msg:'too large to preview' });
    const text = fs.readFileSync(full, 'utf8');
    res.json({ ok:true, name: safe, content: text });
  } catch(e) {
    res.json({ ok:false, msg:'read error' });
  }
});

app.post('/api/file/:name', auth, (req,res) => {
  const safe = path.basename(req.params.name);
  const full = path.join(HOST_DIR, safe);
  if (!/^[a-zA-Z0-9._-]+$/.test(safe)) return res.json({ ok:false, msg:'invalid name' });
  try {
    fs.writeFileSync(full, String(req.body.content || ''), 'utf8');
    res.json({ ok:true });
  } catch(e) {
    res.json({ ok:false, msg:'write error' });
  }
});

/* ─────────── detect runner ─────────── */
function detectRunner(filename) {
  const ext = path.extname(filename).toLowerCase();
  switch(ext) {
    case '.py':  return { cmd: process.platform==='win32' ? 'python' : 'python3', args: [] };
    case '.js':
    case '.mjs': return { cmd: 'node', args: [] };
    case '.sh':  return { cmd: process.platform==='win32' ? null : 'bash', args: [] };
    default:     return null;
  }
}

/* ─────────── spawn + stream ─────────── */
function startProcess(opts) {
  const runId = newRunId();
  const proc = spawn(opts.cmd, opts.args, {
    cwd: HOST_DIR,
    env: { ...process.env, PYTHONUNBUFFERED: '1', NODE_ENV: 'production', TERM: 'xterm-256color' },
    detached: process.platform !== 'win32',
  });

  const run = {
    runId,
    file: opts.file || null,
    cmd: opts.displayCmd || opts.cmd,
    proc,
    startTime: Date.now(),
    stdout: '', stderr: '',
    exitCode: null, done: false,
    listeners: new Set(),
  };
  processes.set(runId, run);

  const broadcast = obj => { for (const fn of run.listeners) { try { fn(obj); } catch(e){} } };

  proc.stdout.on('data', chunk => {
    const s = chunk.toString();
    run.stdout += s;
    if (run.stdout.length > 1024*1024) run.stdout = run.stdout.slice(-1024*1024);
    broadcast({ t:'out', d: s });
  });
  proc.stderr.on('data', chunk => {
    const s = chunk.toString();
    run.stderr += s;
    if (run.stderr.length > 1024*1024) run.stderr = run.stderr.slice(-1024*1024);
    broadcast({ t:'err', d: s });
  });
  proc.on('error', err => {
    run.stderr += '\n' + err.message;
    broadcast({ t:'err', d: '\n' + err.message });
  });
  proc.on('exit', (code, sig) => {
    run.done = true;
    run.exitCode = code;
    broadcast({ t:'exit', code, sig });
    setTimeout(() => processes.delete(runId), 5*60*1000);
  });

  return run;
}

function killTree(pid) {
  if (process.platform === 'win32') {
    try { execSync(`taskkill /pid ${pid} /T /F`); } catch(e){}
    return;
  }
  try { process.kill(-pid, 'SIGTERM'); } catch(e) {
    try { process.kill(pid, 'SIGTERM'); } catch(e2){}
  }
  setTimeout(() => {
    try { process.kill(-pid, 'SIGKILL'); } catch(e) {}
  }, 3000);
}

/* ─────────── run a file ─────────── */
app.post('/api/run', auth, (req,res) => {
  const { file } = req.body || {};
  if (!file || !/^[a-zA-Z0-9._-]+$/.test(file)) return res.json({ ok:false, msg:'invalid file' });
  const full = path.join(HOST_DIR, file);
  if (!fs.existsSync(full)) return res.json({ ok:false, msg:'file not found' });

  const runner = detectRunner(file);
  if (!runner || !runner.cmd) return res.json({ ok:false, msg:'cannot execute this file type' });

  // already running?
  for (const [id, r] of processes) {
    if (r.file === file && !r.done) return res.json({ ok:false, msg:'already running', runId: id });
  }

  const displayCmd = `${runner.cmd} ${file}`;
  const run = startProcess({
    cmd: runner.cmd,
    args: [...runner.args, full],
    file,
    displayCmd,
  });
  res.json({ ok:true, runId: run.runId, cmd: displayCmd });
});

/* ─────────── stop a process ─────────── */
app.post('/api/stop', auth, (req,res) => {
  const { runId } = req.body || {};
  if (!runId) return res.json({ ok:false, msg:'no runId' });
  const run = processes.get(runId);
  if (!run) return res.json({ ok:false, msg:'not found' });
  if (run.done) return res.json({ ok:false, msg:'already exited' });
  killTree(run.proc.pid);
  res.json({ ok:true });
});

/* ─────────── list processes ─────────── */
app.get('/api/processes', auth, (req,res) => {
  const list = [];
  for (const [id, r] of processes) {
    if (!r.done) list.push({ runId: id, file: r.file, cmd: r.cmd, startTime: r.startTime, pid: r.proc.pid });
  }
  res.json({ ok:true, processes: list });
});

/* ─────────── live stream (SSE) ─────────── */
app.get('/api/stream/:runId', auth, (req,res) => {
  const run = processes.get(req.params.runId);
  if (!run) return res.status(404).json({ ok:false, msg:'not found' });

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders?.();

  const send = obj => { try { res.write('data: ' + JSON.stringify(obj) + '\n\n'); } catch(e){} };

  // replay buffer
  if (run.stdout) send({ t:'out', d: run.stdout });
  if (run.stderr) send({ t:'err', d: run.stderr });
  if (run.done) { send({ t:'exit', code: run.exitCode }); return res.end(); }

  const listener = obj => send(obj);
  run.listeners.add(listener);

  const keepAlive = setInterval(() => { try { res.write(': ping\n\n'); } catch(e){} }, 15000);

  req.on('close', () => {
    clearInterval(keepAlive);
    run.listeners.delete(listener);
  });
});

/* ─────────── real terminal ─────────── */
app.post('/api/terminal', auth, (req,res) => {
  const cmd = String(req.body.cmd || '').trim();
  if (!cmd) return res.json({ ok:false, msg:'empty command' });
  if (/^(sudo|su|shutdown|reboot|mkfs)\b|rm\s+-rf\s+\//.test(cmd))
    return res.json({ ok:false, msg:'blocked by policy' });

  const isWin = process.platform === 'win32';
  const shell = isWin ? 'powershell.exe' : '/bin/bash';
  const args  = isWin ? ['-NoProfile', '-Command', cmd] : ['-lc', cmd];

  const run = startProcess({ cmd: shell, args, displayCmd: cmd });
  res.json({ ok:true, runId: run.runId });
});

/* ─────────── startup / shutdown ─────────── */
process.on('exit', () => {
  for (const [, r] of processes) {
    try { killTree(r.proc.pid); } catch(e){}
  }
});
['SIGINT','SIGTERM'].forEach(sig => process.on(sig, () => process.exit(0)));

app.listen(PORT, '0.0.0.0', () => {
  console.log('════════════════════════════════════════════════');
  console.log('  SUKUNA HOSTING PANEL v4.0 — REAL BACKEND');
  console.log('  URL  : http://0.0.0.0:' + PORT);
  console.log('  USER : ' + USER);
  console.log('  HOST : ' + HOST_DIR);
  console.log('  MODE : REAL · python / node / bash execution');
  console.log('════════════════════════════════════════════════');
});
