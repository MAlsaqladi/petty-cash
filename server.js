/**
 * خادم Node.js/Express — الوسيط الوحيد بين المتصفح وقاعدة بيانات Supabase.
 *
 * المتصفح لا يعرف أي شيء عن Supabase إطلاقًا (لا رابط ولا مفتاح).
 * كل طلب من الواجهة يمر عبر مسار واحد POST /api/db، والذي يستخدم
 * مفتاح service_role السرّي (من متغيرات بيئة Render) للاتصال الفعلي
 * بقاعدة البيانات على الخادم فقط.
 */
const express = require('express');
const path = require('path');
const compression = require('compression');
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || '';

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.warn('⚠ تحذير: متغيرات البيئة SUPABASE_URL و SUPABASE_SERVICE_KEY غير معرّفة. أضفهما من Render → Environment.');
}

const supabase = SUPABASE_URL && SUPABASE_SERVICE_KEY
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, { auth: { persistSession: false } })
  : null;

const ATTACHMENTS_BUCKET = 'attachments';
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 }, // 8MB
  fileFilter: (req, file, cb) => {
    const ok = /^image\//.test(file.mimetype) || file.mimetype === 'application/pdf';
    cb(ok ? null : new Error('نوع الملف غير مدعوم — يُسمح فقط بالصور أو ملفات PDF'), ok);
  }
});

app.use(compression());
app.use(express.json({ limit: '2mb' }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});

/* -------------------------------------------------------------------
   المسار الوحيد للتواصل مع قاعدة البيانات — بروكسي بسيط ومحكوم
   ------------------------------------------------------------------- */
const ALLOWED_TABLES = new Set([
  'federations', 'users', 'users_public', 'cost_centers', 'expense_types',
  'custodies', 'custody_budgets', 'custody_transfers', 'custody_closures'
]);
const ALLOWED_RPC = new Set(['login', 'change_password']);

// أنواع المستخدمين الممنوعة من تسجيل الدخول إلى أي نظام (سجلات فقط، بلا وصول)
const NO_LOGIN_USER_TYPES = new Set(['لاعب', 'حكم', 'متعاون']);

app.post('/api/db', async (req, res) => {
  if (!supabase) {
    return res.status(500).json({ data: null, error: { message: 'الخادم غير مهيّأ بعد: أضف SUPABASE_URL و SUPABASE_SERVICE_KEY في إعدادات البيئة على Render.' } });
  }
  const { op, table, payload, pkField, id, patch, returning, fn, args } = req.body || {};
  try {
    let query;
    if (op === 'select') {
      if (!ALLOWED_TABLES.has(table)) return res.status(400).json({ data: null, error: { message: 'جدول غير مسموح: ' + table } });
      query = supabase.from(table).select('*');
    } else if (op === 'insert') {
      if (!ALLOWED_TABLES.has(table)) return res.status(400).json({ data: null, error: { message: 'جدول غير مسموح: ' + table } });
      query = supabase.from(table).insert(payload);
      if (returning) query = query.select().single();
    } else if (op === 'update') {
      if (!ALLOWED_TABLES.has(table)) return res.status(400).json({ data: null, error: { message: 'جدول غير مسموح: ' + table } });
      query = supabase.from(table).update(patch).eq(pkField, id);
      if (returning) query = query.select().single();
    } else if (op === 'rpc') {
      if (!ALLOWED_RPC.has(fn)) return res.status(400).json({ data: null, error: { message: 'دالة غير مسموحة: ' + fn } });
      query = supabase.rpc(fn, args || {});
    } else {
      return res.status(400).json({ data: null, error: { message: 'عملية غير معروفة: ' + op } });
    }
    let { data, error } = await query;
    if (error) return res.status(200).json({ data: null, error: { message: error.message } });
    // حاجز أمان إضافي على مستوى الخادم: بعض أنواع المستخدمين (لاعب/حكم/متعاون)
    // لا يُسمح لها بتسجيل الدخول إلى أي نظام إطلاقًا، حتى لو كانت بياناتها صحيحة.
    if (op === 'rpc' && fn === 'login' && Array.isArray(data)) {
      data = data.filter(u => !NO_LOGIN_USER_TYPES.has(u.user_type));
    }
    res.json({ data, error: null });
  } catch (e) {
    console.error(e);
    res.status(500).json({ data: null, error: { message: e.message || 'خطأ غير متوقع في الخادم' } });
  }
});

app.get('/healthz', (req, res) => res.status(200).send('ok'));

/* -------------------------------------------------------------------
   المرفقات: رفع ملف، وتوليد رابط مؤقت لعرضه
   ------------------------------------------------------------------- */
app.post('/api/upload', (req, res) => {
  upload.single('file')(req, res, async (err) => {
    if (err) return res.status(400).json({ data: null, error: { message: err.message } });
    if (!supabase) return res.status(500).json({ data: null, error: { message: 'الخادم غير مهيّأ بعد.' } });
    if (!req.file) return res.status(400).json({ data: null, error: { message: 'لم يتم إرفاق أي ملف' } });
    const { folder } = req.body || {};
    const safeFolder = /^[a-z_]+$/.test(folder || '') ? folder : 'misc';
    const ext = (req.file.originalname.split('.').pop() || 'bin').toLowerCase().replace(/[^a-z0-9]/g, '');
    const objectPath = `${safeFolder}/${Date.now()}-${Math.random().toString(16).slice(2,8)}.${ext}`;
    const { error } = await supabase.storage.from(ATTACHMENTS_BUCKET).upload(objectPath, req.file.buffer, {
      contentType: req.file.mimetype,
      upsert: false,
    });
    if (error) return res.status(500).json({ data: null, error: { message: error.message } });
    res.json({ data: { path: objectPath, name: req.file.originalname }, error: null });
  });
});

app.post('/api/file-url', express.json(), async (req, res) => {
  if (!supabase) return res.status(500).json({ data: null, error: { message: 'الخادم غير مهيّأ بعد.' } });
  const { path: objectPath } = req.body || {};
  if (!objectPath) return res.status(400).json({ data: null, error: { message: 'مسار الملف مطلوب' } });
  const { data, error } = await supabase.storage.from(ATTACHMENTS_BUCKET).createSignedUrl(objectPath, 600);
  if (error) return res.status(500).json({ data: null, error: { message: error.message } });
  res.json({ data: { url: data.signedUrl }, error: null });
});

/* -------------------------------------------------------------------
   تقديم الواجهة الثابتة (index.html)
   ------------------------------------------------------------------- */
// login.html هي نقطة الدخول الرئيسية (اختيار النظام ثم تسجيل الدخول).
// index.html = نظام العهد النقدية، secondments.html = نظام الانتدابات وتذاكر السفر.
app.use(express.static(path.join(__dirname), { extensions: ['html'], index: 'login.html', maxAge: '5m' }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));

app.listen(PORT, () => {
  console.log(`✓ الخادم يعمل على المنفذ ${PORT}`);
  console.log(supabase ? '✓ متصل بإعدادات Supabase' : '✗ إعدادات Supabase ناقصة');
});
