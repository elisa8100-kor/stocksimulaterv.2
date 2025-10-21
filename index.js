// backend/server.js
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import SQLite from 'better-sqlite3';
import { nanoid } from 'nanoid';
import rateLimit from 'express-rate-limit';

const {
  PORT = 4000,
  JWT_SECRET = 'dev_secret',
  CORS_ORIGIN = 'http://127.0.0.1:5500',
  ADMIN_PASSWORD = ''
} = process.env;

const app = express();
app.use(helmet());
app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: CORS_ORIGIN, credentials: true }));

/* ================== DB ================== */
const db = new SQLite('./db.sqlite');
db.pragma('journal_mode = WAL');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  account_id TEXT UNIQUE NOT NULL,
  nickname TEXT NOT NULL,
  pwd_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'USER',
  pin_hash TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS login_failures (
  account_id TEXT PRIMARY KEY,
  count INTEGER NOT NULL DEFAULT 0,
  cool_until INTEGER NOT NULL DEFAULT 0,
  hard_until INTEGER NOT NULL DEFAULT 0,
  last_ts INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS tickets (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  category TEXT,
  title TEXT,
  body TEXT,
  meta_json TEXT,
  status TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS risk_logs (
  id TEXT PRIMARY KEY,
  actor_account TEXT,
  action TEXT,
  result TEXT,
  device TEXT,
  detail_json TEXT,
  ip TEXT,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_use (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  ymd TEXT,
  created_at INTEGER NOT NULL,
  UNIQUE(user_id, ymd)
);

CREATE TABLE IF NOT EXISTS points (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  balance INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sim_states (
  user_id TEXT PRIMARY KEY,
  state_json TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
`);

/* ================== 유틸 ================== */
const now = () => Date.now();
const dayStr = (d=new Date()) => d.toISOString().slice(0,10);

const badWords = ['bad','shit','fuck','욕','바보'];
const hasBadWord = (s='') => {
  const t = String(s).toLowerCase();
  return badWords.some(w => t.includes(w));
};

function signToken(user) {
  return jwt.sign({ uid: user.id, role: user.role, accountId: user.account_id }, JWT_SECRET, { expiresIn: '8h' });
}
function requireAuth(req, res, next) {
  try {
    const token = req.cookies['token'];
    if (!token) return res.status(401).json({ ok: false, msg: 'no token' });
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ ok: false, msg: 'invalid token' });
  }
}
function requireAdmin(req, res, next) {
  if (req.user?.role === 'PERMANENT_ADMIN') return next();
  return res.status(403).json({ ok: false, msg: 'admin only' });
}

const RATE_LIMIT_HARD = 30;
const addFail = db.prepare(`
  INSERT INTO login_failures(account_id,count,cool_until,hard_until,last_ts)
  VALUES(@account_id,1,0,0,@ts)
  ON CONFLICT(account_id) DO UPDATE SET
    count = login_failures.count + 1,
    last_ts = @ts,
    cool_until = CASE 
      WHEN login_failures.count+1 >= 16 AND login_failures.count+1 < ${RATE_LIMIT_HARD} THEN @cool
      ELSE login_failures.cool_until
    END,
    hard_until = CASE 
      WHEN login_failures.count+1 >= ${RATE_LIMIT_HARD} THEN @hard
      ELSE login_failures.hard_until
    END
  WHERE account_id=@account_id
`);
const getFail = db.prepare(`SELECT * FROM login_failures WHERE account_id=?`);
const resetFail = db.prepare(`DELETE FROM login_failures WHERE account_id=?`);

/* ================== API ================== */

// 회원가입: 비속어 필터 추가
app.post('/register', (req, res) => {
  const { accountId, nickname, password, pin } = req.body || {};
  if (!/^[A-Za-z0-9_]{4,16}$/.test(accountId||'')) return res.status(400).json({ ok:false, msg:'invalid accountId' });
  if (!nickname || nickname.length<2 || nickname.length>16) return res.status(400).json({ ok:false, msg:'invalid nickname' });
  if (!password || password.length<4 || password.length>64) return res.status(400).json({ ok:false, msg:'invalid password' });
  if (hasBadWord(accountId) || hasBadWord(nickname)) return res.status(400).json({ ok:false, msg:'profanity not allowed' });

  const pwd_hash = bcrypt.hashSync(password, 10);
  const pin_hash = pin ? bcrypt.hashSync(pin, 10) : null;

  const user = {
    id: 'u_'+nanoid(12),
    account_id: accountId,
    nickname,
    pwd_hash,
    role: 'USER',
    pin_hash,
    created_at: now()
  };

  try {
    db.prepare(`INSERT INTO users (id,account_id,nickname,pwd_hash,role,pin_hash,created_at) 
                VALUES (@id,@account_id,@nickname,@pwd_hash,@role,@pin_hash,@created_at)`).run(user);
    return res.json({ ok:true });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return res.status(409).json({ ok:false, msg:'account exists' });
    return res.status(500).json({ ok:false, msg:'server error' });
  }
});

// 로그인: 비속어 계정/닉네임이면 로그인 거부
app.post('/login', (req, res) => {
  const { accountId, password } = req.body || {};
  const fail = getFail.get(accountId||'_');
  const ts = now();
  if (fail) {
    if (fail.hard_until && fail.hard_until > ts) {
      return res.status(423).json({ ok:false, hard:true, until:fail.hard_until });
    }
    if (fail.cool_until && fail.cool_until > ts) {
      return res.status(429).json({ ok:false, cool:true, until:fail.cool_until });
    }
  }

  const user = db.prepare(`SELECT * FROM users WHERE account_id=?`).get(accountId);
  if (user && (hasBadWord(user.account_id) || hasBadWord(user.nickname))) {
    return res.status(403).json({ ok:false, msg:'account contains profanity; contact support' });
  }

  if (!user || !bcrypt.compareSync(password||'', user.pwd_hash)) {
    const cool = ts + (fail?.count>=15 ? 60_000 : (fail?.count>=5 ? 30_000 : 0));
    const hard = (fail?.count>=RATE_LIMIT_HARD-1) ? ts + 5*60_000 : (fail?.hard_until||0);
    addFail.run({ account_id: accountId, ts, cool, hard });
    const cur = getFail.get(accountId);
    return res.status(401).json({ ok:false, failCount: cur?.count||1, cool: !!cur?.cool_until && cur.cool_until>ts, hard: !!cur?.hard_until && cur.hard_until>ts, until: cur?.hard_until || cur?.cool_until || 0 });
  }

  resetFail.run(accountId);
  const token = signToken(user);
  res.cookie('token', token, {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
    maxAge: 8*60*60*1000
  });
  return res.json({ ok:true, user:{ id:user.id, accountId:user.account_id, nickname:user.nickname, role:user.role } });
});

app.post('/logout', (_req, res) => {
  res.clearCookie('token');
  return res.json({ ok:true });
});

app.get('/me', requireAuth, (req, res) => {
  const u = db.prepare(`SELECT id,account_id as accountId,nickname,role FROM users WHERE id=?`).get(req.user.uid);
  return res.json({ ok:true, user: u });
});

app.post('/recovery', (req, res) => {
  const { accountId, pin } = req.body || {};
  const user = db.prepare(`SELECT * FROM users WHERE account_id=?`).get(accountId);
  if (!user || !user.pin_hash) return res.status(400).json({ ok:false, msg:'no pin set' });
  const ok = bcrypt.compareSync(pin||'', user.pin_hash);
  if (!ok) return res.status(401).json({ ok:false, msg:'pin mismatch' });
  resetFail.run(accountId);
  return res.json({ ok:true });
});

app.post('/pin/set', requireAuth, (req, res) => {
  const { pin } = req.body || {};
  if (!/^\d{6,8}$/.test(pin||'')) return res.status(400).json({ ok:false, msg:'PIN 6~8 digits' });
  db.prepare(`UPDATE users SET pin_hash=? WHERE id=?`).run(bcrypt.hashSync(pin,10), req.user.uid);
  return res.json({ ok:true });
});

// 티켓
app.post('/tickets', requireAuth, (req, res) => {
  const { category, title, body, meta } = req.body || {};
  const t = {
    id: 't_'+nanoid(12),
    user_id: req.user.uid,
    category, title, body,
    meta_json: JSON.stringify(meta||{}),
    status: '접수',
    created_at: now()
  };
  db.prepare(`INSERT INTO tickets(id,user_id,category,title,body,meta_json,status,created_at) 
              VALUES(@id,@user_id,@category,@title,@body,@meta_json,@status,@created_at)`).run(t);
  return res.json({ ok:true, ticketId:t.id });
});

app.get('/tickets', requireAuth, (req, res) => {
  const isAdmin = req.user.role === 'PERMANENT_ADMIN';
  const rows = isAdmin
    ? db.prepare(`SELECT * FROM tickets ORDER BY created_at DESC LIMIT 500`).all()
    : db.prepare(`SELECT * FROM tickets WHERE user_id=? ORDER BY created_at DESC LIMIT 50`).all(req.user.uid);
  return res.json({ ok:true, items: rows });
});

// 오늘 고유 관리자 수 + OTK
app.post('/admin-use', requireAuth, (req, res) => {
  const ymd = dayStr();
  try {
    db.prepare(`INSERT INTO admin_use(id,user_id,ymd,created_at) VALUES(?,?,?,?)`).run('a_'+nanoid(10), req.user.uid, ymd, now());
  } catch {}
  return res.json({ ok:true });
});
app.get('/admin-count', (_req, res) => {
  const ymd = dayStr();
  const row = db.prepare(`SELECT COUNT(*) AS cnt FROM admin_use WHERE ymd=?`).get(ymd);
  return res.json({ ok:true, count: row.cnt|0 });
});
app.post('/otk/verify', requireAuth, (req, res) => {
  const { input } = req.body || {};
  const row = db.prepare(`SELECT COUNT(*) AS cnt FROM admin_use WHERE ymd=?`).get(dayStr());
  const expect = 'ADMIN2025243295+' + Math.round((row.cnt|0) * 3.14);
  if (input !== expect) return res.status(401).json({ ok:false, msg:'OTK 불일치' });

  const u = db.prepare(`SELECT * FROM users WHERE id=?`).get(req.user.uid);
  const tempPayload = { uid: u.id, role: 'TEMP_ADMIN', accountId: u.account_id, temp_admin_until: now() + 20*60*1000 };
  const token = jwt.sign(tempPayload, JWT_SECRET, { expiresIn: '8h' });
  res.cookie('token', token, { httpOnly:true, sameSite:'lax', secure:false, maxAge:8*60*60*1000 });
  try { db.prepare(`INSERT INTO admin_use(id,user_id,ymd,created_at) VALUES(?,?,?,?)`).run('a_'+nanoid(10), u.id, dayStr(), now()); } catch {}
  return res.json({ ok:true, until: tempPayload.temp_admin_until });
});

// 위험 로그
app.post('/risk-action', requireAuth, (req, res) => {
  const { action, details, device } = req.body || {};
  const ip = req.headers['x-forwarded-for']?.toString().split(',')[0] || req.socket.remoteAddress || '';
  const id = 'r_'+nanoid(12);
  db.prepare(`INSERT INTO risk_logs(id,actor_account,action,result,device,detail_json,ip,created_at)
              VALUES(?,?,?,?,?,?,?,?)`).run(
    id, req.user.accountId, action, 'accepted', device||'', JSON.stringify(details||{}), ip, now()
  );
  return res.json({ ok:true, logId: id });
});
app.get('/risk-log', requireAuth, requireAdmin, (_req, res) => {
  const rows = db.prepare(`SELECT * FROM risk_logs ORDER BY created_at DESC LIMIT 200`).all();
  res.json({ ok:true, items: rows });
});

// 포인트
app.post('/points/add', requireAuth, requireAdmin, (req, res) => {
  const { userId, delta=0, reason='achievement' } = req.body || {};
  let row = db.prepare(`SELECT * FROM points WHERE user_id=?`).get(userId);
  if (!row) {
    row = { id:'p_'+nanoid(10), user_id:userId, balance:0, updated_at:now() };
    db.prepare(`INSERT INTO points(id,user_id,balance,updated_at) VALUES(?,?,?,?)`).run(row.id,row.user_id,row.balance,row.updated_at);
  }
  const newBal = (row.balance|0) + (delta|0);
  db.prepare(`UPDATE points SET balance=?, updated_at=? WHERE user_id=?`).run(newBal, now(), userId);
  return res.json({ ok:true, balance:newBal, reason });
});
app.get('/points', requireAuth, (req,res)=>{
  const row = db.prepare(`SELECT balance FROM points WHERE user_id=?`).get(req.user.uid);
  return res.json({ ok:true, balance: row?.balance|0 });
});

// 관리자 비번 로그인 (3연타 모달용)
const adminPwLimiter = rateLimit({ windowMs: 60_000, max: 5 });
app.post('/admin-login', requireAuth, adminPwLimiter, (req, res) => {
  const { password } = req.body || {};
  if (!password || password !== ADMIN_PASSWORD) {
    return res.status(401).json({ ok:false, msg:'invalid admin password' });
  }
  db.prepare(`UPDATE users SET role='PERMANENT_ADMIN' WHERE id=?`).run(req.user.uid);
  const fresh = db.prepare(`SELECT * FROM users WHERE id=?`).get(req.user.uid);
  const token = jwt.sign({ uid:fresh.id, role:fresh.role, accountId:fresh.account_id }, JWT_SECRET, { expiresIn: '8h' });
  res.cookie('token', token, { httpOnly:true, sameSite:'lax', secure:false, maxAge:8*60*60*1000 });
  try {
    db.prepare(`INSERT INTO admin_use(id,user_id,ymd,created_at) VALUES(?,?,?,?)`)
      .run('a_'+nanoid(10), fresh.id, dayStr(), now());
  } catch {}
  return res.json({ ok:true, role:fresh.role });
});

// 시뮬 상태 저장/조회
app.get('/sim/state', requireAuth, (req, res) => {
  const row = db.prepare(`SELECT state_json FROM sim_states WHERE user_id=?`).get(req.user.uid);
  if (!row) return res.json({ ok:true, state:null });
  try { return res.json({ ok:true, state: JSON.parse(row.state_json) }); }
  catch { return res.json({ ok:true, state:null }); }
});
app.put('/sim/state', requireAuth, (req, res) => {
  const { state } = req.body || {};
  if (!state) return res.status(400).json({ ok:false, msg:'no state' });
  const payload = JSON.stringify(state);
  if (payload.length > 1_000_000) return res.status(413).json({ ok:false, msg:'state too large' });
  const ts = Date.now();
  db.prepare(`
    INSERT INTO sim_states(user_id, state_json, updated_at)
    VALUES(?,?,?)
    ON CONFLICT(user_id) DO UPDATE SET state_json=excluded.state_json, updated_at=excluded.updated_at
  `).run(req.user.uid, payload, ts);
  return res.json({ ok:true, updated_at: ts });
});

app.listen(PORT, () => {
  console.log(`API listening on http://localhost:${PORT}`);
});
