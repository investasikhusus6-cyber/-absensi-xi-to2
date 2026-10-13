const crypto = require('crypto'), express = require('express'), bcrypt = require('bcryptjs');
const mysql = require('mysql2/promise'), ExcelJS = require('exceljs');

const NAMES = ["ADAM HUSEIN","AFAN AGUSTINA RAMADHAN","AHMAD WILDAN NULKARIM","AL FAREZA","ALAN FIRMANSYAH","ALIF APRIYANSYAH","ARDI KURNIAWAN","AYATULLOH","BINTANG FARIZ PRATAMA","BUKHORI ATMAJAYA","DWI AFIAN SAPUTRA","FATHUL ULUM","FAUZAN","HAFIS","ITFANUL ASWAR","JIBRAN KHALIK","KHAERUL UMAM","MAULANA IQBAL SHOFAR","MUHAMAD ADAM SUBARKAH","MUHAMAD GALIH","MUHAMAD RIZKY FEBRIANSYAH","MUHAMAD SAEFUL BAHRI","MUHAMMAD NAZAR","MUWADIKHUL ULUM","NUR RAMADAN","NURFATAH","RIDO PRATAMA","SAEFUL ANWAR","SLAMET TIYO PURNOMO","SUKMAJAYA","TANTRIO","TAUFIK HIDAYATULLAH","WAHYU HIDAYAT"];
const ST = ['Hadir','Sakit','Izin','Alpa','Bolos'], SE = ['Pagi','Sore'];
const CODE = { Hadir: '✓', Sakit: 'S', Izin: 'I', Alpa: 'A', Bolos: 'B' };
const E = process.env;

const db = mysql.createPool({ host: E.DB_HOST || 'localhost', user: E.DB_USER || 'root', password: E.DB_PASS || '',
  database: E.DB_NAME || 'absensi', port: +E.DB_PORT || 3306, dateStrings: true, connectionLimit: 2,
  ssl: E.DB_SSL === 'false' ? undefined : { minVersion: 'TLSv1.2' } });

const app = express();
app.use(express.json({ limit: '10kb' }));
const SECRET = E.SESSION_SECRET;
if (!SECRET || SECRET.length < 16) throw new Error('SESSION_SECRET wajib diisi (minimal 16 karakter)');
const sign = p => crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
const mkTok = id => { const p = Buffer.from(JSON.stringify({ id, exp: Date.now() + 8 * 3600e3 })).toString('base64url'); return p + '.' + sign(p); };
const readTok = req => {
  const m = /(?:^|; )sid=([^;]+)/.exec(req.headers.cookie || ''); if (!m) return null;
  const [p, sg] = m[1].split('.'); if (!p || !sg) return null;
  const a = Buffer.from(sg), b = Buffer.from(sign(p)); if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try { const o = JSON.parse(Buffer.from(p, 'base64url')); return o.exp > Date.now() ? o.id : null; } catch { return null; }
};
const setCk = (res, v, age) => res.setHeader('Set-Cookie', `sid=${v}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${age}${E.NODE_ENV === 'production' || E.VERCEL ? '; Secure' : ''}`);

// Tabel, 33 siswa, dan admin pertama disiapkan otomatis (sekali per instance)
let ready;
const init = () => ready || (ready = (async () => {
  await db.query('CREATE TABLE IF NOT EXISTS admins(id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(50) NOT NULL UNIQUE, password_hash VARCHAR(100) NOT NULL)');
  await db.query('CREATE TABLE IF NOT EXISTS students(id INT PRIMARY KEY, name VARCHAR(100) NOT NULL UNIQUE)');
  await db.query("CREATE TABLE IF NOT EXISTS attendance(student_id INT NOT NULL, att_date DATE NOT NULL, session ENUM('Pagi','Sore') NOT NULL, status ENUM('Hadir','Sakit','Izin','Alpa','Bolos') NOT NULL, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP, PRIMARY KEY(student_id,att_date,session), FOREIGN KEY(student_id) REFERENCES students(id))");
  await db.query('INSERT IGNORE INTO students(id,name) VALUES ?', [NAMES.map((n, i) => [i + 1, n])]);
  const [[c]] = await db.query('SELECT COUNT(*) n FROM admins');
  if (!c.n) {
    const pw = E.ADMIN_PASS || crypto.randomBytes(6).toString('hex');
    await db.query('INSERT INTO admins(username,password_hash) VALUES(?,?)', [E.ADMIN_USER || 'admin', await bcrypt.hash(pw, 12)]);
    console.log(`Admin dibuat -> username: ${E.ADMIN_USER || 'admin'}${E.ADMIN_PASS ? '' : ' | kata sandi: ' + pw}`);
  }
})());
app.use('/api', (q, r, n) => init().then(() => n(), e => { console.error(e); ready = null; r.status(500).json({ error: 'Database tidak terhubung' }); }));
app.use(express.static('public'));

const okDate = d => /^\d{4}-\d{2}-\d{2}$/.test(d || '') && !isNaN(Date.parse(d));
const auth = (req, res, next) => { const id = readTok(req); if (!id) return res.status(401).json({ error: 'Belum login' }); req.adminId = id; next(); };
const bad = (res, m) => res.status(400).json({ error: m });
const wrap = f => (req, res) => f(req, res).catch(e => { console.error(e); res.status(500).json({ error: 'Kesalahan server' }); });

// Percobaan login dibatasi sederhana: 8x per 10 menit per IP
const tries = {};
app.post('/api/login', wrap(async (req, res) => {
  const ip = req.ip, now = Date.now(); tries[ip] = (tries[ip] || []).filter(t => now - t < 600e3);
  if (tries[ip].length >= 8) return res.status(429).json({ error: 'Terlalu banyak percobaan, coba lagi nanti' });
  const { username, password } = req.body || {};
  const [[u]] = await db.query('SELECT * FROM admins WHERE username=?', [String(username || '')]);
  if (!u || !(await bcrypt.compare(String(password || ''), u.password_hash))) { tries[ip].push(now); return res.status(401).json({ error: 'Username atau kata sandi salah' }); }
  setCk(res, mkTok(u.id), 8 * 3600); res.json({ ok: true, username: u.username });
}));
app.post('/api/logout', (req, res) => { setCk(res, '', 0); res.json({ ok: true }); });
app.get('/api/me', (req, res) => res.json({ loggedIn: !!readTok(req) }));

app.post('/api/password', auth, wrap(async (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (typeof newPassword !== 'string' || newPassword.length < 8) return bad(res, 'Kata sandi baru minimal 8 karakter');
  const [[u]] = await db.query('SELECT * FROM admins WHERE id=?', [req.adminId]);
  if (!(await bcrypt.compare(String(oldPassword || ''), u.password_hash))) return bad(res, 'Kata sandi lama salah');
  await db.query('UPDATE admins SET password_hash=? WHERE id=?', [await bcrypt.hash(newPassword, 12), u.id]);
  res.json({ ok: true });
}));

app.get('/api/students', auth, wrap(async (q, res) => res.json((await db.query('SELECT id,name FROM students ORDER BY id'))[0])));

app.get('/api/attendance', auth, wrap(async (req, res) => {
  const { date, session: s } = req.query; if (!okDate(date) || !SE.includes(s)) return bad(res, 'Tanggal/sesi tidak valid');
  const [r] = await db.query('SELECT student_id,status FROM attendance WHERE att_date=? AND session=?', [date, s]);
  res.json(Object.fromEntries(r.map(x => [x.student_id, x.status])));
}));

// Ubah satu siswa. status=null -> hapus (kembali "belum diabsen")
app.put('/api/attendance', auth, wrap(async (req, res) => {
  const { date, session: s, student_id, status } = req.body || {};
  if (!okDate(date) || !SE.includes(s) || !Number.isInteger(student_id) || student_id < 1 || student_id > NAMES.length || (status !== null && !ST.includes(status))) return bad(res, 'Data tidak valid');
  if (status === null) await db.query('DELETE FROM attendance WHERE student_id=? AND att_date=? AND session=?', [student_id, date, s]);
  else await db.query('INSERT INTO attendance(student_id,att_date,session,status) VALUES(?,?,?,?) ON DUPLICATE KEY UPDATE status=VALUES(status)', [student_id, date, s, status]);
  res.json({ ok: true });
}));

app.post('/api/attendance/all-present', auth, wrap(async (req, res) => {
  const { date, session: s } = req.body || {}; if (!okDate(date) || !SE.includes(s)) return bad(res, 'Tanggal/sesi tidak valid');
  await db.query(`INSERT INTO attendance(student_id,att_date,session,status) SELECT id,?,?,'Hadir' FROM students ON DUPLICATE KEY UPDATE status='Hadir'`, [date, s]);
  res.json({ ok: true });
}));

app.delete('/api/attendance', auth, wrap(async (req, res) => {
  const { date, session: s } = req.query; if (!okDate(date) || !SE.includes(s)) return bad(res, 'Tanggal/sesi tidak valid');
  await db.query('DELETE FROM attendance WHERE att_date=? AND session=?', [date, s]); res.json({ ok: true });
}));

app.get('/api/history/:id', auth, wrap(async (req, res) => {
  const id = parseInt(req.params.id, 10); if (!(id >= 1 && id <= NAMES.length)) return bad(res, 'Siswa tidak valid');
  const [r] = await db.query("SELECT att_date d,session s,status FROM attendance WHERE student_id=? ORDER BY att_date DESC, FIELD(session,'Sore','Pagi')", [id]);
  res.json(r);
}));

// Rekap bulanan: persentase hadir per siswa pada bulan (YYYY-MM)
app.get('/api/monthly', auth, wrap(async (req, res) => {
  const m = String(req.query.month || ''); if (!/^\d{4}-\d{2}$/.test(m)) return bad(res, 'Bulan tidak valid');
  const [r] = await db.query(`SELECT s.id,s.name,SUM(a.status='Hadir') hadir,COUNT(a.status) total FROM students s
    LEFT JOIN attendance a ON a.student_id=s.id AND DATE_FORMAT(a.att_date,'%Y-%m')=? GROUP BY s.id,s.name ORDER BY s.id`, [m]);
  res.json(r.map(x => ({ ...x, hadir: +x.hadir || 0, total: +x.total, persen: x.total ? Math.round(100 * (x.hadir || 0) / x.total) : null })));
}));

app.get('/api/export', auth, wrap(async (req, res) => {
  const { from, to, session: s } = req.query;
  if (!okDate(from) || !okDate(to) || from > to || !['Pagi', 'Sore', 'Both'].includes(s)) return bad(res, 'Filter tidak valid');
  const [rows] = await db.query(`SELECT student_id,att_date d,session s,status FROM attendance WHERE att_date BETWEEN ? AND ? ${s === 'Both' ? '' : 'AND session=?'}
    ORDER BY att_date, FIELD(session,'Pagi','Sore')`, s === 'Both' ? [from, to] : [from, to, s]);
  const cols = [], seen = new Set(), map = {};
  for (const r of rows) { const k = r.d + '|' + r.s; if (!seen.has(k)) { seen.add(k); cols.push({ d: r.d, s: r.s, k }); } map[k + '|' + r.student_id] = r.status; }
  const lbl = c => `${c.d.slice(8)}/${c.d.slice(5, 7)} ${c.s}`;
  const wb = new ExcelJS.Workbook(), head = { bold: true, color: { argb: 'FFFFFFFF' } }, fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF10233F' } };
  const hdr = row => row.eachCell(c => { c.font = head; c.fill = fill; c.alignment = { horizontal: 'center' }; });
  const box = ws => ws.eachRow(r => r.eachCell(c => c.border = { top: { style: 'thin' }, left: { style: 'thin' }, bottom: { style: 'thin' }, right: { style: 'thin' } }));

  const w1 = wb.addWorksheet('REKAP ABSENSI');
  hdr(w1.addRow(['No.', 'Nama Siswa', ...cols.map(lbl)]));
  NAMES.forEach((n, i) => { const r = w1.addRow([i + 1, n, ...cols.map(c => CODE[map[`${c.k}|${i + 1}`]] || '')]); r.eachCell((c, x) => { if (x > 2) c.alignment = { horizontal: 'center' }; }); });
  w1.getColumn(1).width = 6; w1.getColumn(2).width = 34; cols.forEach((_, i) => w1.getColumn(i + 3).width = 13); w1.views = [{ state: 'frozen', xSplit: 2, ySplit: 1 }]; box(w1);

  const w2 = wb.addWorksheet('REKAP KETERANGAN'); w2.columns = [{ width: 6 }, { width: 34 }, { width: 14 }, { width: 12 }];
  ['Sakit', 'Izin', 'Alpa', 'Bolos'].forEach((st, i) => {
    const t = w2.addRow([`${'ABCD'[i]}. ${st.toUpperCase()}`]); t.font = { bold: true, size: 13 };
    hdr(w2.addRow(['No.', 'Nama Siswa', 'Tanggal', 'Sesi Apel'])); let n = 0; const stu = new Set();
    NAMES.forEach((name, j) => cols.forEach(c => { if (map[`${c.k}|${j + 1}`] === st) { w2.addRow([++n, name, `${c.d.slice(8)}/${c.d.slice(5, 7)}/${c.d.slice(0, 4)}`, c.s]); stu.add(j); } }));
    if (!n) w2.addRow(['', '(tidak ada)']);
    const j = w2.addRow(['', `Jumlah siswa: ${stu.size} (${n} catatan)`]); j.font = { bold: true }; w2.addRow([]);
  });

  const w3 = wb.addWorksheet('STATISTIK'); hdr(w3.addRow(['Tanggal', 'Sesi', ...ST, 'Belum Diabsen', '% Hadir']));
  cols.forEach(c => { const n = Object.fromEntries(ST.map(x => [x, 0])); NAMES.forEach((_, j) => { const v = map[`${c.k}|${j + 1}`]; if (v) n[v]++; });
    const done = ST.reduce((a, x) => a + n[x], 0); w3.addRow([`${c.d.slice(8)}/${c.d.slice(5, 7)}/${c.d.slice(0, 4)}`, c.s, ...ST.map(x => n[x]), NAMES.length - done, done ? Math.round(100 * n.Hadir / done) + '%' : '']); });
  w3.columns.forEach(c => c.width = 15); box(w3);

  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', `attachment; filename="rekap_absensi_XI-TO-2_${from}_${to}.xlsx"`);
  await wb.xlsx.write(res); res.end();
}));

if (!E.VERCEL) init().then(() => app.listen(E.PORT || 3000, () => console.log('Berjalan di port ' + (E.PORT || 3000))));
module.exports = app;
