require('dotenv').config();
const express = require('express'), helmet = require('helmet'), rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken'), { Pool } = require('pg'), path = require('path');

const SECRET = process.env.JWT_SECRET;
if (!SECRET || !process.env.DATABASE_URL) { console.error('Set JWT_SECRET and DATABASE_URL'); process.exit(1); }
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: process.env.DATABASE_URL.includes('localhost') ? false : { rejectUnauthorized: false } });
const app = express();
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
    unlocked_at timestamptz default now(), submitted_at timestamptz, unique(user_id, video_id));`);
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
  if (phone && !phoneOk(phone)) throw bad('Enter a valid phone number');
  const refUser = ref ? (await pool.query('select id from users where code=$1', [ref])).rows[0] : null;
  const code = (name.trim().split(' ')[0].replace(/\W/g, '') || 'user') + Math.floor(100 + Math.random() * 900);
  const isAdmin = !!process.env.ADMIN_EMAIL && email.toLowerCase() === process.env.ADMIN_EMAIL.toLowerCase();
  try {
    const { rows } = await pool.query(
      'insert into users(name,email,phone,pass_hash,code,referred_by,is_admin) values($1,$2,$3,$4,$5,$6,$7) returning *',
      [name.trim(), email.toLowerCase(), phone || null, await bcrypt.hash(password, 10), code, refUser?.id || null, isAdmin]);
    res.json({ token: token(rows[0]) });
  } catch (e) { if (e.code === '23505') throw bad('Email already registered', 409); throw e; }
}));

app.post('/api/auth/login', authLimit, h(async (req, res) => {
  const { rows } = await pool.query('select * from users where email=$1', [(req.body.email || '').toLowerCase()]);
  if (!rows[0] || !(await bcrypt.compare(req.body.password || '', rows[0].pass_hash))) throw bad('Wrong email or password', 401);
  res.json({ token: token(rows[0]) });
}));

// ---------- member routes ----------
app.get('/api/me', auth(), h(async (req, res) => {
  const u = req.user;
  const [d, r, lf] = await Promise.all([
    pool.query("select count(*)::int c from submissions where user_id=$1 and status='Approved'", [u.id]),
    pool.query('select count(*)::int c from users where referred_by=$1', [u.id]),
    pool.query('select coalesce(sum(amount),0)::int s from txs where user_id=$1 and amount>0', [u.id])]);
  const refs = r.rows[0].c, [tier, next] = tierOf(refs);
  res.json({ id: u.id, name: u.name, email: u.email, phone: u.phone, isAdmin: u.is_admin, balance: u.balance, pending: u.pending,
    done: d.rows[0].c, lifetime: lf.rows[0].s, refs, refReward: refs * 50, tier, nextTier: next, code: u.code,
    link: (process.env.BASE_URL || '') + '/?ref=' + u.code });
}));

app.get('/api/tasks', auth(), h(async (req, res) => {
  const { rows } = await pool.query(`select id,title,description,reward,minutes,icon from tasks t where active
    and not exists(select 1 from submissions s where s.task_id=t.id and s.user_id=$1) order by id`, [req.user.id]);
  res.json(rows);
}));

app.post('/api/tasks/:id/submit', auth(), h(async (req, res) => {
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

app.post('/api/withdrawals', auth(), h(async (req, res) => {
  const amount = parseInt(req.body.amount, 10), phone = String(req.body.phone || '').trim();
  if (!phoneOk(phone)) throw bad('Enter a valid M-Pesa number');
  if (!(amount >= 100)) throw bad('Minimum withdrawal is KES 100');
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

app.get('/api/videos', auth(), h(async (req, res) => {
  const { rows } = await pool.query(`select v.id,v.title,v.reward,v.unlock_fee,v.duration_secs,v.youtube_id,c.status,
      greatest(0, v.duration_secs - extract(epoch from (now()-c.unlocked_at))::int) as wait_left
    from videos v left join video_claims c on c.video_id=v.id and c.user_id=$1
    where v.active or c.id is not null order by v.id desc`, [req.user.id]);
  // the YouTube id is only sent once the member has unlocked the video
  res.json(rows.map(r => ({ id: r.id, title: r.title, reward: r.reward, unlockFee: r.unlock_fee, duration: r.duration_secs,
    status: r.status || 'Locked', waitLeft: r.status === 'Unlocked' ? r.wait_left : 0, youtubeId: r.status ? r.youtube_id : null })));
}));

app.post('/api/videos/:id/unlock', auth(), h(async (req, res) => {
  const yt = await withTx(async c => {
    const v = (await c.query('select * from videos where id=$1 and active', [req.params.id])).rows[0];
    if (!v) throw bad('Video not available', 404);
    try { await c.query('insert into video_claims(user_id,video_id) values($1,$2)', [req.user.id, v.id]); }
    catch (e) { if (e.code === '23505') throw bad('You already unlocked this video', 409); throw e; }
    const ok = await c.query('update users set balance=balance-$1 where id=$2 and balance>=$1 returning id', [v.unlock_fee, req.user.id]);
    if (!ok.rowCount) throw bad('Not enough balance. Earn KES ' + v.unlock_fee + ' from tasks first.');
    if (v.unlock_fee > 0) await log(c, req.user.id, 'Unlocked video: ' + v.title, -v.unlock_fee);
    return v.youtube_id;
  });
  res.json({ youtubeId: yt });
}));

app.post('/api/videos/:id/proof', auth(), h(async (req, res) => {
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
  const { title, url, reward, unlockFee, duration } = req.body, yt = ytId(url);
  if (!title || !yt) throw bad('Enter a title and a valid YouTube link');
  if (!(reward > 0) || !(unlockFee >= 0) || !(duration >= 10)) throw bad('Check the reward, unlock fee and video length (10+ seconds)');
  res.json((await pool.query('insert into videos(title,youtube_id,reward,unlock_fee,duration_secs) values($1,$2,$3,$4,$5) returning id',
    [title, yt, reward, unlockFee, duration])).rows[0]);
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

// ---------- frontend ----------
app.get('/', (_, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.use('/api', (_, res) => res.status(404).json({ error: 'Not found' }));

init().then(() => app.listen(process.env.PORT || 3000, () => console.log('Taskora running'))).catch(e => { console.error(e); process.exit(1); });
