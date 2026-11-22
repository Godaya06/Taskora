require('dotenv').config();
const express = require('express'), helmet = require('helmet'), rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'), { Pool } = require('pg'), path = require('path');

const SECRET = process.env.JWT_SECRET;
if (!SECRET || !process.env.DATABASE_URL) { console.error('Set JWT_SECRET and DATABASE_URL'); process.exit(1); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false } });
const app = express();
app.set('trust proxy', 1); // Render sits behind a proxy; needed so rate limits count each visitor separately
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '50kb' }));

// ---------- helpers ----------
const bad = (m, s = 400) => Object.assign(new Error(m), { status: s });
const h = fn => (req, res) => fn(req, res).catch(e => { if (!e.status) console.error(e); res.status(e.status || 500).json({ error: e.status ? e.message : 'Server error' }); });
async function withTx(fn) {
  const c = await pool.connect();
  try { await c.query('begin'); const r = await fn(c); await c.query('commit'); return r; }
  catch (e) { await c.query('rollback'); throw e; } finally { c.release(); }
}
const auth = adminOnly => async (req, res, next) => {
  try {
    const { id } = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), SECRET);
    const { rows } = await pool.query('select * from users where id=$1', [id]);
    if (!rows[0]) throw 0;
    if (adminOnly && !rows[0].is_admin) return res.status(403).json({ error: 'Admins only' });
    req.user = rows[0]; next();
  } catch { res.status(401).json({ error: 'Please log in' }); }
};
const tierOf = r => r >= 10 ? ['Platinum', null] : r >= 6 ? ['Gold', 'Platinum'] : r >= 3 ? ['Silver', 'Gold'] : ['Bronze', 'Silver'];
const phoneOk = p => /^(07|01|\+?254)\d{7,9}$/.test(String(p).replace(/\s/g, ''));
const log = (c, uid, text, amount) => c.query('insert into txs(user_id,text,amount) values($1,$2,$3)', [uid, text, amount]);

// ---------- database ----------
async function init() {
  await pool.query(`
  create table if not exists users(id serial primary key, name text not null, email text unique not null, phone text, pass_hash text not null,
    code text unique not null, referred_by int references users(id), ref_paid boolean default false, balance int default 0, pending int default 0,
    is_admin boolean default false, created_at timestamptz default now());
  create table if not exists tasks(id serial primary key, title text not null, description text, reward int not null, minutes int default 10, icon text default '📋', active boolean default true);
  create table if not exists submissions(id serial primary key, user_id int references users(id), task_id int references tasks(id), answer text,
    status text default 'Pending', created_at timestamptz default now(), unique(user_id, task_id));
  create table if not exists withdrawals(id serial primary key, user_id int references users(id), amount int not null, phone text not null, status text default 'Processing', created_at timestamptz default now());
  create table if not exists txs(id serial primary key, user_id int references users(id), text text, amount int, created_at timestamptz default now());
  create table if not exists videos(id serial primary key, title text not null, youtube_id text not null, reward int not null, unlock_fee int not null default 0, duration_secs int not null default 60, active boolean default true, created_at timestamptz default now());
  create table if not exists video_claims(id serial primary key, user_id int references users(id), video_id int references videos(id), status text default 'Unlocked', comment text, channel text,
    unlocked_at timestamptz default now(), submitted_at timestamptz, unique(user_id, video_id));
  create table if not exists payments(id serial primary key, user_id int references users(id), phone text, amount int, checkout_id text unique, receipt text, status text default 'Pending', note text, created_at timestamptz default now());
  create unique index if not exists payments_receipt_uq on payments(receipt) where receipt is not null;
  alter table users add column if not exists activated boolean default true;
  alter table users add column if not exists package text;
  alter table users add column if not exists package_until timestamptz;
  alter table payments add column if not exists purpose text default 'activation';
  alter table payments add column if not exists package text;
  alter table payments add column if not exists video_id int;
  alter table videos add column if not exists slots int;
  update videos set slots=0 where slots is null;
  alter table users add column if not exists verified boolean default true;
  alter table users add column if not exists spin_available boolean default false;
  create table if not exists otps(id serial primary key, phone text not null, purpose text not null, code_hash text not null, attempts int default 0, used boolean default false, created_at timestamptz default now(), expires_at timestamptz not null);
  create index if not exists otps_lookup on otps(phone, purpose, id desc);
  create table if not exists surveys(id serial primary key, title text not null, description text, reward int not null, questions jsonb not null, active boolean default true, created_at timestamptz default now());
  create table if not exists survey_responses(id serial primary key, user_id int references users(id), survey_id int references surveys(id), answers jsonb, status text default 'Pending', created_at timestamptz default now(), unique(user_id, survey_id));`);
  const { rows } = await pool.query('select count(*)::int c from tasks');
  if (!rows[0].c) await pool.query(`insert into tasks(title,description,reward,minutes,icon) values
    ('Product Survey – Laptops','Answer a short survey about laptop brands.',120,12,'💻'),
    ('Online Shopping Feedback','Share your experience with online stores.',100,10,'🛒'),
    ('Mobile App Test','Test our new mobile app and give feedback.',150,15,'📱')`);
}

// ---------- auth ----------
const authLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });
const token = u => jwt.sign({ id: u.id }, SECRET, { expiresIn: '30d' });

app.post('/api/auth/register', authLimit, h(async (req, res) => {
  const { name, email, password, phone, ref } = req.body;
  if (!name?.trim() || !/^\S+@\S+\.\S+$/.test(email || '')) throw bad('Enter your name and a valid email');
  if ((password || '').length < 8) throw bad('Password must be at least 8 characters');
  if (!phoneOk(phone || '')) throw bad('Enter a valid M-Pesa phone number like 0712345678');
  const norm = normPhone(phone);
  if (process.env.ALLOW_DUP_PHONES !== 'true' && (await pool.query('select 1 from users where phone=$1 or phone=$2 or phone=$3', [norm, '0' + norm.slice(3), String(phone).trim()])).rowCount) throw bad('This phone number is already registered', 409);
  const refUser = ref ? (await pool.query('select id from users where code=$1', [ref])).rows[0] : null;
  const code = (name.trim().split(' ')[0].replace(/\W/g, '') || 'user') + Math.floor(100 + Math.random() * 900);
  const isAdmin = !!process.env.ADMIN_EMAIL && email.toLowerCase() === process.env.ADMIN_EMAIL.toLowerCase();
  try {
    const { rows } = await pool.query(
      'insert into users(name,email,phone,pass_hash,code,referred_by,is_admin,activated,verified) values($1,$2,$3,$4,$5,$6,$7,$7,$8) returning *',
      [name.trim(), email.toLowerCase(), norm, await bcrypt.hash(password, 10), code, refUser?.id || null, isAdmin, isAdmin || OTP_MODE === 'off']);
    let otpSent = false;
    if (!rows[0].verified) { try { await issueOtp(norm, 'signup'); otpSent = true; } catch (e) { console.error('OTP send failed:', e.message); } }
    res.json({ token: token(rows[0]), otpSent });
  } catch (e) { if (e.code === '23505') throw bad('Email already registered', 409); throw e; }
}));

app.post('/api/auth/login', authLimit, h(async (req, res) => {
  const { rows } = await pool.query('select * from users where email=$1', [(req.body.email || '').toLowerCase()]);
  if (!rows[0] || !(await bcrypt.compare(req.body.password || '', rows[0].pass_hash))) throw bad('Wrong email or password', 401);
  res.json({ token: token(rows[0]) });
}));

// ---------- account activation (one-time M-Pesa payment) ----------
const FEE = parseInt(process.env.ACTIVATION_FEE || '70', 10);
const PACKAGE_DAYS = parseInt(process.env.PACKAGE_DAYS || '30', 10);
const crypto = require('crypto');
const needActive = (req, res, next) => req.user.verified === false ? res.status(403).json({ error: 'Verify your phone number first', code: 'NOT_VERIFIED' })
  : (req.user.activated || req.user.is_admin) ? next() : res.status(402).json({ error: 'Activate your account first', code: 'NOT_ACTIVATED' });

// ---------- settings: minimum withdrawal, OTP codes, free spin ----------
const MIN_WITHDRAW = parseInt(process.env.MIN_WITHDRAW || '500', 10);
// OTP_MODE: 'sms' when Africa's Talking is configured; 'log' (testing only, prints codes in the server log); otherwise 'off'
const OTP_MODE = (process.env.AT_API_KEY && process.env.AT_USERNAME) ? 'sms' : (process.env.OTP_MODE === 'log' ? 'log' : 'off');
const SPIN_ON = process.env.SPIN_ENABLED !== 'false';
const SPIN = [{ label: 'Try again', prize: 0, w: 40 }, { label: 'KES 5', prize: 5, w: 30 }, { label: 'KES 10', prize: 10, w: 20 }, { label: 'KES 20', prize: 20, w: 8 }, { label: 'KES 50', prize: 50, w: 2 }]; // weights add up to 100
const otpHash = (code, phone, purpose) => crypto.createHmac('sha256', SECRET).update(code + '|' + phone + '|' + purpose).digest('hex');
async function sendSms(to, message) {
  const base = process.env.AT_ENV === 'sandbox' ? 'https://api.sandbox.africastalking.com' : 'https://api.africastalking.com';
  const body = new URLSearchParams({ username: process.env.AT_USERNAME, to: '+' + to, message });
  if (process.env.AT_SENDER_ID) body.set('from', process.env.AT_SENDER_ID);
  const r = await fetch(base + '/version1/messaging', { method: 'POST', body, signal: AbortSignal.timeout(20000),
    headers: { apiKey: process.env.AT_API_KEY, Accept: 'application/json', 'Content-Type': 'application/x-www-form-urlencoded' } });
  const j = await r.json().catch(() => ({}));
  const rec = j.SMSMessageData && j.SMSMessageData.Recipients && j.SMSMessageData.Recipients[0];
  if (!r.ok || !rec || !/success/i.test(rec.status || '')) { console.error('SMS error', r.status, JSON.stringify(j).slice(0, 300)); throw bad('Couldn’t send the code. Try again shortly.', 502); }
}
async function issueOtp(phone, purpose) {
  if (OTP_MODE === 'off') return;
  const last = (await pool.query('select created_at from otps where phone=$1 and purpose=$2 order by id desc limit 1', [phone, purpose])).rows[0];
  if (last && Date.now() - new Date(last.created_at) < 60000) throw bad('Please wait a minute before asking for another code', 429);
  const n = (await pool.query(`select count(*)::int c from otps where phone=$1 and created_at > now() - interval '1 hour'`, [phone])).rows[0].c;
  if (n >= 5) throw bad('Too many codes requested. Try again later.', 429);
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
  await pool.query(`insert into otps(phone,purpose,code_hash,expires_at) values($1,$2,$3,now()+interval '10 minutes')`, [phone, purpose, otpHash(code, phone, purpose)]);
  if (OTP_MODE === 'log') console.log('TEST OTP for', phone, purpose, code);
  else await sendSms(phone, 'Your Taskora code is ' + code + '. It expires in 10 minutes. Never share it.');
}
async function checkOtp(phone, purpose, code) {
  const o = (await pool.query(`select * from otps where phone=$1 and purpose=$2 and not used and expires_at>now() order by id desc limit 1`, [phone, purpose])).rows[0];
  if (!o || o.attempts >= 5 || !/^\d{6}$/.test(code)) return false;
  const a = Buffer.from(otpHash(code, phone, purpose)), b = Buffer.from(o.code_hash);
  const ok = a.length === b.length && crypto.timingSafeEqual(a, b);
  await pool.query(ok ? 'update otps set used=true where id=$1' : 'update otps set attempts=attempts+1 where id=$1', [o.id]);
  return ok;
}
const cbSecret = crypto.createHmac('sha256', SECRET).update('mpesa-callback').digest('hex').slice(0, 32);
const darajaReady = () => ['DARAJA_CONSUMER_KEY', 'DARAJA_CONSUMER_SECRET', 'DARAJA_SHORTCODE', 'DARAJA_PASSKEY', 'BASE_URL'].every(k => process.env[k]);
const mBase = () => process.env.DARAJA_ENV === 'production' ? 'https://api.safaricom.co.ke' : 'https://sandbox.safaricom.co.ke';
const stamp = () => new Date().toLocaleString('sv-SE', { timeZone: 'Africa/Nairobi' }).replace(/\D/g, '');
const normPhone = p => { const d = String(p).replace(/\D/g, ''); return d.startsWith('254') ? d : '254' + d.replace(/^0/, ''); };
async function darajaPost(path, body) {
  const tr = await fetch(mBase() + '/oauth/v1/generate?grant_type=client_credentials', {
    headers: { Authorization: 'Basic ' + Buffer.from(process.env.DARAJA_CONSUMER_KEY + ':' + process.env.DARAJA_CONSUMER_SECRET).toString('base64') }, signal: AbortSignal.timeout(20000) });
  const t = (await tr.json().catch(() => ({}))).access_token;
  if (!t) throw bad('Payment service is unavailable. Try again shortly.', 502);
  const r = await fetch(mBase() + path, { method: 'POST', headers: { Authorization: 'Bearer ' + t, 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(25000) });
  return r.json().catch(() => ({}));
}
const stkAuth = () => { const ts = stamp(); return { BusinessShortCode: process.env.DARAJA_SHORTCODE, Timestamp: ts,
  Password: Buffer.from(process.env.DARAJA_SHORTCODE + process.env.DARAJA_PASSKEY + ts).toString('base64') }; };
async function activateFor(c, paymentId, receipt) {
  const p = (await c.query(`update payments set status='Success', receipt=$2 where id=$1 and status='Pending' returning user_id,purpose,package,video_id`, [paymentId, receipt || null])).rows[0];
  if (!p) return;
  if (p.purpose === 'package') await c.query('update users set activated=true, package=$2, package_until=now()+make_interval(days => $3::int) where id=$1', [p.user_id, p.package, PACKAGE_DAYS]);
  else if (p.purpose === 'video') await c.query('insert into video_claims(user_id,video_id) values($1,$2) on conflict (user_id,video_id) do nothing', [p.user_id, p.video_id]);
  else await c.query('update users set activated=true, spin_available=$2 where id=$1', [p.user_id, SPIN_ON]);
}

app.post('/api/activation/pay', auth(), rateLimit({ windowMs: 60 * 1000, max: 5 }), h(async (req, res) => {
  if (req.user.verified === false) throw bad('Verify your phone number first', 403);
  if (req.user.activated) throw bad('Your account is already active');
  if (!phoneOk(req.body.phone)) throw bad('Enter a valid M-Pesa number like 0712345678');
  if (!darajaReady()) throw bad('Online payment isn’t set up yet. Please contact support.', 503);
  const phone = normPhone(req.body.phone);
  const r = await darajaPost('/mpesa/stkpush/v1/processrequest', { ...stkAuth(),
    TransactionType: process.env.DARAJA_TRANSACTION_TYPE || 'CustomerPayBillOnline', Amount: FEE, PartyA: phone,
    PartyB: process.env.DARAJA_PARTYB || process.env.DARAJA_SHORTCODE, PhoneNumber: phone,
    CallBackURL: process.env.BASE_URL.replace(/\/$/, '') + '/api/pay/hook/' + cbSecret, AccountReference: 'Taskora', TransactionDesc: 'Account activation' });
  if (r.ResponseCode !== '0') { console.error('STK push error', r); throw bad('Couldn’t start the payment. Check the number and try again.' + (process.env.DARAJA_ENV === 'production' ? '' : ' [Safaricom: ' + (r.errorMessage || r.ResponseDescription || 'no details') + ']'), 502); }
  await pool.query('insert into payments(user_id,phone,amount,checkout_id) values($1,$2,$3,$4)', [req.user.id, phone, FEE, r.CheckoutRequestID]);
  res.json({ ok: true });
}));

app.get('/api/activation/status', auth(), h(async (req, res) => {
  if (req.user.activated) return res.json({ activated: true });
  const p = (await pool.query('select * from payments where user_id=$1 order by id desc limit 1', [req.user.id])).rows[0];
  if (p && p.status === 'Pending' && Date.now() - new Date(p.created_at) > 15000 && darajaReady()) { // callback late? ask Safaricom directly
    const q = await darajaPost('/mpesa/stkpushquery/v1/query', { ...stkAuth(), CheckoutRequestID: p.checkout_id });
    if (q.ResultCode !== undefined) {
      if (String(q.ResultCode) === '0') { await withTx(c => activateFor(c, p.id, null)); return res.json({ activated: true }); }
      await pool.query(`update payments set status='Failed', note=$2 where id=$1 and status='Pending'`, [p.id, String(q.ResultDesc || '').slice(0, 200)]);
      p.status = 'Failed';
    }
  }
  res.json({ activated: false, status: p ? p.status : 'None', message: p && p.status === 'Failed' ? 'The payment was cancelled or failed. Please try again.' : undefined });
}));

app.post('/api/pay/hook/:secret', h(async (req, res) => { // called by Safaricom
  const a = Buffer.from(req.params.secret), b = Buffer.from(cbSecret);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw bad('Not found', 404);
  const cb = req.body && req.body.Body && req.body.Body.stkCallback;
  if (cb && cb.CheckoutRequestID) {
    const items = Object.fromEntries(((cb.CallbackMetadata && cb.CallbackMetadata.Item) || []).map(i => [i.Name, i.Value]));
    try {
      await withTx(async c => {
        const p = (await c.query(`select * from payments where checkout_id=$1 and status='Pending' for update`, [cb.CheckoutRequestID])).rows[0];
        if (!p) return;
        if (cb.ResultCode === 0 && Number(items.Amount) >= p.amount) await activateFor(c, p.id, items.MpesaReceiptNumber);
        else await c.query(`update payments set status='Failed', note=$2 where id=$1`, [p.id, String(cb.ResultDesc || 'Amount mismatch').slice(0, 200)]);
      });
    } catch (e) { console.error('callback error', e); }
  }
  res.json({ ResultCode: 0, ResultDesc: 'Accepted' });
}));

// ---------- member routes ----------
app.get('/api/me', auth(), h(async (req, res) => {
  const u = req.user;
  const [d, r, lf] = await Promise.all([
    pool.query("select count(*)::int c from submissions where user_id=$1 and status='Approved'", [u.id]),
    pool.query('select count(*)::int c from users where referred_by=$1', [u.id]),
    pool.query('select coalesce(sum(amount),0)::int s from txs where user_id=$1 and amount>0', [u.id])]);
  const refs = r.rows[0].c, [tier, next] = tierOf(refs);
  res.json({ id: u.id, name: u.name, email: u.email, phone: u.phone, isAdmin: u.is_admin, activated: u.activated, activationFee: FEE, verified: u.verified !== false, spin: !!u.spin_available && SPIN_ON, spinSegments: SPIN.map(x => ({ label: x.label, w: x.w })), minWithdraw: MIN_WITHDRAW, balance: u.balance, pending: u.pending,
    done: d.rows[0].c, lifetime: lf.rows[0].s, refs, refReward: refs * 50, tier, nextTier: next, code: u.code,
    link: (process.env.BASE_URL || '') + '/?ref=' + u.code });
}));

app.get('/api/tasks', auth(), needActive, h(async (req, res) => {
  const { rows } = await pool.query(`select id,title,description,reward,minutes,icon from tasks t where active
    and not exists(select 1 from submissions s where s.task_id=t.id and s.user_id=$1) order by id`, [req.user.id]);
  res.json(rows);
}));

app.post('/api/tasks/:id/submit', auth(), needActive, h(async (req, res) => {
  const answer = String(req.body.answer || '').slice(0, 2000);
  await withTx(async c => {
    const t = (await c.query('select * from tasks where id=$1 and active', [req.params.id])).rows[0];
    if (!t) throw bad('Task not found', 404);
    try { await c.query('insert into submissions(user_id,task_id,answer) values($1,$2,$3)', [req.user.id, t.id, answer]); }
    catch (e) { if (e.code === '23505') throw bad('You already did this task', 409); throw e; }
    await c.query('update users set pending=pending+$1 where id=$2', [t.reward, req.user.id]);
  });
  res.json({ ok: true });
}));

app.get('/api/submissions', auth(), h(async (req, res) => {
  res.json((await pool.query(`select s.id,t.title,t.reward,s.status,s.created_at from submissions s join tasks t on t.id=s.task_id
    where s.user_id=$1 order by s.id desc`, [req.user.id])).rows);
}));

app.get('/api/transactions', auth(), h(async (req, res) => {
  res.json((await pool.query('select text,amount,created_at from txs where user_id=$1 order by id desc limit 50', [req.user.id])).rows);
}));

app.post('/api/withdrawals', auth(), needActive, h(async (req, res) => {
  const amount = parseInt(req.body.amount, 10), phone = String(req.body.phone || '').trim();
  if (!phoneOk(phone)) throw bad('Enter a valid M-Pesa number');
  if (!(amount >= MIN_WITHDRAW)) throw bad('Minimum withdrawal is KES ' + MIN_WITHDRAW);
  await withTx(async c => {
    const ok = await c.query('update users set balance=balance-$1 where id=$2 and balance>=$1 returning id', [amount, req.user.id]);
    if (!ok.rowCount) throw bad('Amount is more than your balance');
    await c.query('insert into withdrawals(user_id,amount,phone) values($1,$2,$3)', [req.user.id, amount, phone]);
    await log(c, req.user.id, 'Withdrawal request submitted (M-Pesa)', -amount);
  });
  res.json({ ok: true });
}));

app.get('/api/withdrawals', auth(), h(async (req, res) => {
  res.json((await pool.query('select amount,phone,status,created_at from withdrawals where user_id=$1 order by id desc', [req.user.id])).rows);
}));

// ---------- OTP, password reset and free spin ----------
app.post('/api/otp/verify', auth(), authLimit, h(async (req, res) => {
  if (req.user.verified !== false) return res.json({ ok: true });
  if (!(await checkOtp(normPhone(req.user.phone), 'signup', String(req.body.code || '').trim()))) throw bad('That code is wrong or has expired');
  await pool.query('update users set verified=true where id=$1', [req.user.id]);
  res.json({ ok: true });
}));
app.post('/api/otp/resend', auth(), h(async (req, res) => {
  if (req.user.verified !== false) return res.json({ ok: true });
  await issueOtp(normPhone(req.user.phone), 'signup');
  res.json({ ok: true });
}));
app.post('/api/auth/forgot', authLimit, h(async (req, res) => {
  if (OTP_MODE === 'off') throw bad('Password reset by SMS isn’t available yet. Please contact support.', 503);
  if (!phoneOk(req.body.phone || '')) throw bad('Enter the phone number you registered with');
  const norm = normPhone(req.body.phone);
  const u = (await pool.query('select id from users where phone=$1 or phone=$2', [norm, '0' + norm.slice(3)])).rows[0];
  if (u) { try { await issueOtp(norm, 'reset'); } catch (e) { if (e.status === 429) throw e; console.error('OTP send failed:', e.message); } }
  res.json({ ok: true }); // same answer whether or not the number exists
}));
app.post('/api/auth/reset', authLimit, h(async (req, res) => {
  const { phone, code, password } = req.body;
  if (!phoneOk(phone || '')) throw bad('Enter your phone number');
  if ((password || '').length < 8) throw bad('Password must be at least 8 characters');
  const norm = normPhone(phone);
  if (!(await checkOtp(norm, 'reset', String(code || '').trim()))) throw bad('That code is wrong or has expired');
  const r = await pool.query('update users set pass_hash=$1 where phone=$2 or phone=$3', [await bcrypt.hash(password, 10), norm, '0' + norm.slice(3)]);
  if (!r.rowCount) throw bad('That code is wrong or has expired');
  res.json({ ok: true });
}));
app.post('/api/spin', auth(), needActive, h(async (req, res) => { // one free spin, given when a new member activates
  const out = await withTx(async c => {
    if (!(await c.query('update users set spin_available=false where id=$1 and spin_available returning id', [req.user.id])).rowCount) throw bad('No free spin available');
    let r = crypto.randomInt(0, 100), i = 0;
    for (; i < SPIN.length - 1; i++) { if (r < SPIN[i].w) break; r -= SPIN[i].w; }
    if (SPIN[i].prize > 0) { await c.query('update users set balance=balance+$1 where id=$2', [SPIN[i].prize, req.user.id]); await log(c, req.user.id, 'Free spin bonus', SPIN[i].prize); }
    return { index: i, prize: SPIN[i].prize };
  });
  res.json(out);
}));

// ---------- survey packages and surveys ----------
// A package buys ACCESS to surveys for a number of days. Rewards come from each survey, not from the package price.
const PACKAGES = { Bronze: { price: 500, daily: 3 }, Silver: { price: 1000, daily: 6 }, Gold: { price: 1500, daily: 9 }, Platinum: { price: 2000, daily: 12 } };
const pkgOf = u => (u.package && u.package_until && new Date(u.package_until) > new Date() && PACKAGES[u.package]) ? { name: u.package, until: u.package_until, daily: PACKAGES[u.package].daily } : null;
const effPkg = u => pkgOf(u) || (u.is_admin ? { name: 'Admin', until: new Date(Date.now() + 365 * 864e5), daily: 99 } : null);
const needPackage = (req, res, next) => (req.pkg = effPkg(req.user)) ? next() : res.status(402).json({ error: 'Buy a survey package first', code: 'NO_PACKAGE' });
const usedToday = (c, uid) => c.query(`select count(*)::int c from survey_responses where user_id=$1 and (created_at at time zone 'Africa/Nairobi')::date=(now() at time zone 'Africa/Nairobi')::date`, [uid]).then(r => r.rows[0].c);
async function stkPush(phone, amount, desc) {
  const r = await darajaPost('/mpesa/stkpush/v1/processrequest', { ...stkAuth(),
    TransactionType: process.env.DARAJA_TRANSACTION_TYPE || 'CustomerPayBillOnline', Amount: amount, PartyA: phone,
    PartyB: process.env.DARAJA_PARTYB || process.env.DARAJA_SHORTCODE, PhoneNumber: phone,
    CallBackURL: process.env.BASE_URL.replace(/\/$/, '') + '/api/pay/hook/' + cbSecret, AccountReference: 'Taskora', TransactionDesc: desc });
  if (r.ResponseCode !== '0') { console.error('STK push error', r); throw bad('Couldn’t start the payment. Check the number and try again.' + (process.env.DARAJA_ENV === 'production' ? '' : ' [Safaricom: ' + (r.errorMessage || r.ResponseDescription || 'no details') + ']'), 502); }
  return r.CheckoutRequestID;
}

app.get('/api/surveys', auth(), needActive, h(async (req, res) => {
  const pkg = effPkg(req.user);
  const list = pkg ? (await pool.query(`select s.id,s.title,s.description,s.reward,jsonb_array_length(s.questions)::int as count from surveys s
    where s.active and not exists(select 1 from survey_responses r where r.survey_id=s.id and r.user_id=$1) order by s.id`, [req.user.id])).rows : [];
  res.json({ package: pkg && pkg.name, until: pkg && pkg.until, daily: pkg ? pkg.daily : 0, used: await usedToday(pool, req.user.id), surveys: list,
    packages: Object.entries(PACKAGES).map(([name, p]) => ({ name, price: p.price, daily: p.daily })), days: PACKAGE_DAYS });
}));

app.get('/api/surveys/:id', auth(), needActive, needPackage, h(async (req, res) => {
  const s = (await pool.query('select id,title,description,reward,questions from surveys where id=$1 and active', [req.params.id])).rows[0];
  if (!s) throw bad('Survey not found', 404);
  res.json(s);
}));

app.post('/api/surveys/:id/submit', auth(), needActive, needPackage, h(async (req, res) => {
  const answers = Array.isArray(req.body.answers) ? req.body.answers.map(a => String(a || '').trim().slice(0, 1000)) : [];
  await withTx(async c => {
    await c.query('select id from users where id=$1 for update', [req.user.id]); // one submission at a time per member
    const s = (await c.query('select * from surveys where id=$1 and active', [req.params.id])).rows[0];
    if (!s) throw bad('Survey not found', 404);
    if (answers.length !== s.questions.length || answers.some(a => !a)) throw bad('Please answer every question');
    if (await usedToday(c, req.user.id) >= req.pkg.daily) throw bad('You have reached today’s limit for your package. Come back tomorrow.');
    try { await c.query('insert into survey_responses(user_id,survey_id,answers) values($1,$2,$3)', [req.user.id, s.id, JSON.stringify(answers)]); }
    catch (e) { if (e.code === '23505') throw bad('You already answered this survey', 409); throw e; }
    await c.query('update users set pending=pending+$1 where id=$2', [s.reward, req.user.id]);
  });
  res.json({ ok: true });
}));

app.post('/api/packages/buy', auth(), needActive, rateLimit({ windowMs: 60 * 1000, max: 5 }), h(async (req, res) => {
  const pk = PACKAGES[req.body.package];
  if (!pk) throw bad('Choose a package');
  if (pkgOf(req.user)) throw bad('You already have an active package');
  if (!phoneOk(req.body.phone)) throw bad('Enter a valid M-Pesa number like 0712345678');
  if (!darajaReady()) throw bad('Online payment isn’t set up yet. Please contact support.', 503);
  const phone = normPhone(req.body.phone);
  const checkout = await stkPush(phone, pk.price, req.body.package + ' package');
  await pool.query('insert into payments(user_id,phone,amount,checkout_id,purpose,package) values($1,$2,$3,$4,$5,$6)', [req.user.id, phone, pk.price, checkout, 'package', req.body.package]);
  res.json({ ok: true });
}));

app.get('/api/packages/status', auth(), h(async (req, res) => {
  if (pkgOf(req.user)) return res.json({ active: true });
  const p = (await pool.query(`select * from payments where user_id=$1 and purpose='package' order by id desc limit 1`, [req.user.id])).rows[0];
  if (p && p.status === 'Pending' && Date.now() - new Date(p.created_at) > 15000 && darajaReady()) { // callback late? ask Safaricom directly
    const q = await darajaPost('/mpesa/stkpushquery/v1/query', { ...stkAuth(), CheckoutRequestID: p.checkout_id });
    if (q.ResultCode !== undefined) {
      if (String(q.ResultCode) === '0') { await withTx(c => activateFor(c, p.id, null)); return res.json({ active: true }); }
      await pool.query(`update payments set status='Failed', note=$2 where id=$1 and status='Pending'`, [p.id, String(q.ResultDesc || '').slice(0, 200)]);
      p.status = 'Failed';
    }
  }
  res.json({ active: false, status: p ? p.status : 'None', message: p && p.status === 'Failed' ? 'The payment was cancelled or failed. Please try again.' : undefined });
}));

// ---------- YouTube video tasks ----------
const ytId = u => { const m = String(u || '').match(/(?:youtu\.be\/|v=|shorts\/|embed\/)([A-Za-z0-9_-]{11})/); return m ? m[1] : null; };
async function payReferrer(c, uid) { // pay the referrer once, on the friend's first approved task
  const u = (await c.query('select referred_by,ref_paid from users where id=$1 for update', [uid])).rows[0];
  if (u.referred_by && !u.ref_paid) {
    await c.query('update users set ref_paid=true where id=$1', [uid]);
    await c.query('update users set balance=balance+200 where id=$1', [u.referred_by]);
    await log(c, u.referred_by, 'New referral joined', 200);
  }
}

async function settle(p) { // callback late? ask Safaricom directly
  if (p.status !== 'Pending' || Date.now() - new Date(p.created_at) < 15000 || !darajaReady() || !p.checkout_id) return p.status;
  const q = await darajaPost('/mpesa/stkpushquery/v1/query', { ...stkAuth(), CheckoutRequestID: p.checkout_id });
  if (q.ResultCode === undefined) return 'Pending';
  if (String(q.ResultCode) === '0') { await withTx(c => activateFor(c, p.id, null)); return 'Success'; }
  await pool.query(`update payments set status='Failed', note=$2 where id=$1 and status='Pending'`, [p.id, String(q.ResultDesc || '').slice(0, 200)]);
  return 'Failed';
}

app.get('/api/videos', auth(), needActive, h(async (req, res) => {
  const { rows } = await pool.query(`select v.id,v.title,v.reward,v.unlock_fee,v.duration_secs,v.youtube_id,v.slots,c.status,
      (select count(*)::int from video_claims where video_id=v.id) as taken,
      greatest(0, v.duration_secs - extract(epoch from (now()-c.unlocked_at))::int) as wait_left
    from videos v left join video_claims c on c.video_id=v.id and c.user_id=$1
    where v.active or c.id is not null order by v.id desc`, [req.user.id]);
  // the YouTube id is only sent once the member has unlocked the video
  res.json(rows.map(r => ({ id: r.id, title: r.title, reward: r.reward, unlockFee: r.unlock_fee, duration: r.duration_secs,
    status: r.status || 'Locked', waitLeft: r.status === 'Unlocked' ? r.wait_left : 0, youtubeId: r.status ? r.youtube_id : null,
    slotsLeft: r.slots == null ? null : Math.max(0, r.slots - r.taken) })));
}));

// unlocking a video is paid with M-Pesa (not from the wallet balance)
app.post('/api/videos/:id/pay', auth(), needActive, rateLimit({ windowMs: 60 * 1000, max: 5 }), h(async (req, res) => {
  if (!phoneOk(req.body.phone)) throw bad('Enter a valid M-Pesa number like 0712345678');
  if (!darajaReady()) throw bad('Online payment isn’t set up yet. Please contact support.', 503);
  const phone = normPhone(req.body.phone);
  const r = await withTx(async c => {
    const v = (await c.query('select * from videos where id=$1 and active for update', [req.params.id])).rows[0];
    if (!v) throw bad('Video not available', 404);
    if ((await c.query('select 1 from video_claims where user_id=$1 and video_id=$2', [req.user.id, v.id])).rowCount) throw bad('You already unlocked this video', 409);
    if (v.slots != null) { // count unlocked videos plus payments in progress, so slots can't be oversold
      const n = (await c.query(`select (select count(*) from video_claims where video_id=$1) + (select count(*) from payments where purpose='video' and video_id=$1 and status='Pending' and created_at > now() - interval '10 minutes') as n`, [v.id])).rows[0].n;
      if (Number(n) >= v.slots) throw bad('This video is full. Try another one.', 409);
    }
    if (v.unlock_fee <= 0) { await c.query('insert into video_claims(user_id,video_id) values($1,$2)', [req.user.id, v.id]); return { free: true }; }
    const id = (await c.query(`insert into payments(user_id,phone,amount,purpose,video_id) values($1,$2,$3,'video',$4) returning id`, [req.user.id, phone, v.unlock_fee, v.id])).rows[0].id;
    return { id, fee: v.unlock_fee };
  });
  if (r.free) return res.json({ unlocked: true });
  try {
    const checkout = await stkPush(phone, r.fee, 'Video access');
    await pool.query('update payments set checkout_id=$1 where id=$2', [checkout, r.id]);
  } catch (e) { await pool.query(`update payments set status='Failed', note='STK not sent' where id=$1`, [r.id]); throw e; }
  res.json({ ok: true });
}));

app.get('/api/videos/:id/status', auth(), h(async (req, res) => {
  if ((await pool.query('select 1 from video_claims where user_id=$1 and video_id=$2', [req.user.id, req.params.id])).rowCount) return res.json({ unlocked: true });
  const p = (await pool.query(`select * from payments where user_id=$1 and purpose='video' and video_id=$2 order by id desc limit 1`, [req.user.id, req.params.id])).rows[0];
  const st = p ? await settle(p) : 'None';
  if (st === 'Success') return res.json({ unlocked: true });
  res.json({ unlocked: false, status: st, message: st === 'Failed' ? 'The payment was cancelled or failed. Please try again.' : undefined });
}));

app.post('/api/videos/:id/proof', auth(), needActive, h(async (req, res) => {
  const comment = String(req.body.comment || '').trim().slice(0, 500), channel = String(req.body.channel || '').trim().slice(0, 100);
  if (comment.length < 5) throw bad('Paste the comment you posted on the video');
  if (channel.length < 2) throw bad('Enter your YouTube channel name');
  await withTx(async c => {
    const r = (await c.query(`select c.id,c.status,v.reward,v.duration_secs,extract(epoch from (now()-c.unlocked_at))::int as secs
      from video_claims c join videos v on v.id=c.video_id where c.user_id=$1 and c.video_id=$2 for update of c`, [req.user.id, req.params.id])).rows[0];
    if (!r) throw bad('Unlock the video first', 404);
    if (r.status !== 'Unlocked') throw bad('Proof already submitted');
    if (r.secs < r.duration_secs) throw bad('Watch the whole video first. ' + (r.duration_secs - r.secs) + ' seconds left.');
    await c.query(`update video_claims set status='Pending', comment=$1, channel=$2, submitted_at=now() where id=$3`, [comment, channel, r.id]);
    await c.query('update users set pending=pending+$1 where id=$2', [r.reward, req.user.id]);
  });
  res.json({ ok: true });
}));

// ---------- admin routes ----------
app.post('/api/admin/tasks', auth(true), h(async (req, res) => {
  const { title, description, reward, minutes, icon } = req.body;
  if (!title || !(reward > 0)) throw bad('Title and reward are required');
  res.json((await pool.query('insert into tasks(title,description,reward,minutes,icon) values($1,$2,$3,$4,$5) returning *',
    [title, description || '', reward, minutes || 10, icon || '📋'])).rows[0]);
}));

app.get('/api/admin/submissions', auth(true), h(async (req, res) => {
  res.json((await pool.query(`select s.id,u.name,u.email,t.title,t.reward,s.answer,s.status from submissions s
    join users u on u.id=s.user_id join tasks t on t.id=s.task_id where s.status=$1 order by s.id`, [req.query.status || 'Pending'])).rows);
}));

app.post('/api/admin/submissions/:id/:action', auth(true), h(async (req, res) => {
  const approve = req.params.action === 'approve';
  if (!approve && req.params.action !== 'reject') throw bad('Unknown action', 404);
  await withTx(async c => {
    const s = (await c.query(`select s.*,t.reward,t.title from submissions s join tasks t on t.id=s.task_id where s.id=$1 and s.status='Pending' for update of s`, [req.params.id])).rows[0];
    if (!s) throw bad('Submission not found or already reviewed', 404);
    await c.query('update submissions set status=$1 where id=$2', [approve ? 'Approved' : 'Rejected', s.id]);
    await c.query(`update users set pending=pending-$1, balance=balance+$2 where id=$3`, [s.reward, approve ? s.reward : 0, s.user_id]);
    await log(c, s.user_id, (approve ? 'Task approved: ' : 'Task rejected: ') + s.title, approve ? s.reward : 0);
    if (approve) { // pay the referrer once, on the friend's first approved task
      const u = (await c.query('select referred_by,ref_paid from users where id=$1 for update', [s.user_id])).rows[0];
      if (u.referred_by && !u.ref_paid) {
        await c.query('update users set ref_paid=true where id=$1', [s.user_id]);
        await c.query('update users set balance=balance+200 where id=$1', [u.referred_by]);
        await log(c, u.referred_by, 'New referral joined', 200);
      }
    }
  });
  res.json({ ok: true });
}));

app.get('/api/admin/withdrawals', auth(true), h(async (req, res) => {
  res.json((await pool.query(`select w.id,u.name,w.amount,w.phone,w.status from withdrawals w join users u on u.id=w.user_id
    where w.status=$1 order by w.id`, [req.query.status || 'Processing'])).rows);
}));

app.post('/api/admin/withdrawals/:id/:action', auth(true), h(async (req, res) => {
  const paid = req.params.action === 'paid';
  if (!paid && req.params.action !== 'reject') throw bad('Unknown action', 404);
  await withTx(async c => {
    const w = (await c.query(`select * from withdrawals where id=$1 and status='Processing' for update`, [req.params.id])).rows[0];
    if (!w) throw bad('Withdrawal not found or already handled', 404);
    await c.query('update withdrawals set status=$1 where id=$2', [paid ? 'Paid' : 'Rejected', w.id]);
    if (!paid) { await c.query('update users set balance=balance+$1 where id=$2', [w.amount, w.user_id]); await log(c, w.user_id, 'Withdrawal refunded', w.amount); }
  });
  res.json({ ok: true });
}));

app.post('/api/admin/videos', auth(true), h(async (req, res) => {
  const { title, url, reward, unlockFee, duration, slots } = req.body, yt = ytId(url);
  if (!title || !yt) throw bad('Enter a title and a valid YouTube link');
  if (!(reward > 0) || !(unlockFee >= 0) || !(duration >= 10) || !(slots >= 1)) throw bad('Check the reward, unlock fee, video length (10+ seconds) and number of slots');
  res.json((await pool.query('insert into videos(title,youtube_id,reward,unlock_fee,duration_secs,slots) values($1,$2,$3,$4,$5,$6) returning id',
    [title, yt, reward, unlockFee, duration, slots])).rows[0]);
}));

app.get('/api/admin/claims', auth(true), h(async (req, res) => {
  res.json((await pool.query(`select c.id,u.name,u.email,v.title,v.youtube_id,v.reward,c.comment,c.channel from video_claims c
    join users u on u.id=c.user_id join videos v on v.id=c.video_id where c.status=$1 order by c.id`, [req.query.status || 'Pending'])).rows);
}));

app.post('/api/admin/claims/:id/:action', auth(true), h(async (req, res) => {
  const approve = req.params.action === 'approve';
  if (!approve && req.params.action !== 'reject') throw bad('Unknown action', 404);
  await withTx(async c => {
    const r = (await c.query(`select c.*,v.reward,v.title from video_claims c join videos v on v.id=c.video_id where c.id=$1 and c.status='Pending' for update of c`, [req.params.id])).rows[0];
    if (!r) throw bad('Proof not found or already reviewed', 404);
    await c.query('update video_claims set status=$1 where id=$2', [approve ? 'Approved' : 'Rejected', r.id]);
    await c.query('update users set pending=pending-$1, balance=balance+$2 where id=$3', [r.reward, approve ? r.reward : 0, r.user_id]);
    await log(c, r.user_id, (approve ? 'Video approved: ' : 'Video rejected: ') + r.title, approve ? r.reward : 0);
    if (approve) await payReferrer(c, r.user_id);
  });
  res.json({ ok: true });
}));

app.post('/api/admin/surveys', auth(true), h(async (req, res) => {
  const { title, description, reward, questions } = req.body;
  const qs = (Array.isArray(questions) ? questions : []).filter(q => q && String(q.q || '').trim())
    .map(q => ({ q: String(q.q).trim().slice(0, 300), options: Array.isArray(q.options) ? q.options.map(o => String(o).trim()).filter(Boolean).slice(0, 8) : [] }));
  if (!title || !(reward > 0) || !qs.length) throw bad('Add a title, a reward and at least one question');
  res.json((await pool.query('insert into surveys(title,description,reward,questions) values($1,$2,$3,$4) returning id', [title, description || '', reward, JSON.stringify(qs)])).rows[0]);
}));

app.get('/api/admin/survey-responses', auth(true), h(async (req, res) => {
  res.json((await pool.query(`select r.id,u.name,u.email,s.title,s.reward,s.questions,r.answers from survey_responses r
    join users u on u.id=r.user_id join surveys s on s.id=r.survey_id where r.status=$1 order by r.id`, [req.query.status || 'Pending'])).rows);
}));

app.post('/api/admin/survey-responses/:id/:action', auth(true), h(async (req, res) => {
  const approve = req.params.action === 'approve';
  if (!approve && req.params.action !== 'reject') throw bad('Unknown action', 404);
  await withTx(async c => {
    const r = (await c.query(`select r.*,s.reward,s.title from survey_responses r join surveys s on s.id=r.survey_id where r.id=$1 and r.status='Pending' for update of r`, [req.params.id])).rows[0];
    if (!r) throw bad('Response not found or already reviewed', 404);
    await c.query('update survey_responses set status=$1 where id=$2', [approve ? 'Approved' : 'Rejected', r.id]);
    await c.query('update users set pending=pending-$1, balance=balance+$2 where id=$3', [r.reward, approve ? r.reward : 0, r.user_id]);
    await log(c, r.user_id, (approve ? 'Survey approved: ' : 'Survey rejected: ') + r.title, approve ? r.reward : 0);
    if (approve) await payReferrer(c, r.user_id);
  });
  res.json({ ok: true });
}));

app.get('/api/admin/users', auth(true), h(async (req, res) => {
  res.json((await pool.query('select id,name,email,phone,created_at from users where not activated order by id desc limit 30')).rows);
}));
app.post('/api/admin/users/:id/activate', auth(true), h(async (req, res) => {
  if (!(await pool.query('update users set activated=true where id=$1 returning id', [req.params.id])).rowCount) throw bad('Member not found', 404);
  res.json({ ok: true });
}));

// ---------- frontend ----------
app.get('/', (_, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.use('/api', (_, res) => res.status(404).json({ error: 'Not found' }));

init().then(() => app.listen(process.env.PORT || 3000, () => console.log('Taskora running'))).catch(e => { console.error(e); process.exit(1); });
