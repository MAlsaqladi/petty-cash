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
    const { data, error } = await query;
    if (error) return res.status(200).json({ data: null, error: { message: error.message } });
    res.json({ data, error: null });
  } catch (e) {
    console.error(e);
    res.status(500).json({ data: null, error: { message: e.message || 'خطأ غير متوقع في الخادم' } });
  }
});

app.get('/healthz', (req, res) => res.status(200).send('ok'));

/* -------------------------------------------------------------------
   تقديم الواجهة الثابتة (index.html)
   ------------------------------------------------------------------- */
app.use(express.static(path.join(__dirname), { extensions: ['html'], index: 'index.html', maxAge: '5m' }));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, () => {
  console.log(`✓ الخادم يعمل على المنفذ ${PORT}`);
  console.log(supabase ? '✓ متصل بإعدادات Supabase' : '✗ إعدادات Supabase ناقصة');
});
