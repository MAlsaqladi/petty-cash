/**
 * خادم Node.js/Express — الوسيط الوحيد بين المتصفح وقاعدة بيانات Supabase.
 *
 * المتصفح لا يعرف أي شيء عن Supabase إطلاقًا (لا رابط ولا مفتاح).
 * كل طلب من الواجهة يمر عبر مسار واحد POST /api/db، والذي يستخدم
 * مفتاح service_role السرّي (من متغيرات بيئة Render) للاتصال الفعلي
 * بقاعدة البيانات على الخادم فقط.
 *
 * =========================================================================
 * طبقة الأمان (مهم جدًا — اقرأ هذا قبل التعديل):
 * =========================================================================
 * هذا المسار كان في السابق بروكسي "مفتوح" — أي طلب HTTP يصل إليه (حتى لو لم
 * يمر عبر الواجهة إطلاقًا) كان يُنفَّذ مباشرة على قاعدة البيانات بصلاحية
 * service_role الكاملة، بدون أي تحقق من هوية المُرسِل. الآن:
 *   1) كل عملية (عدا تسجيل الدخول) تتطلب رمز جلسة (token) صالح وموقَّع من
 *      الخادم، يُصدَر فقط بعد تسجيل دخول ناجح، ويُتحقَّق منه ومن صلاحية
 *      المستخدم (حالته ونوعه) من قاعدة البيانات مباشرة في كل طلب.
 *   2) كل قراءة/كتابة على الجداول المرتبطة باتحاد تُقيَّد تلقائيًا باتحاد
 *      المستخدم المسجّل دخوله (عدا "مراجع" الذي يرى كل الاتحادات كما في
 *      تصميم الواجهة أصلاً) — بحيث لا يقدر أي مستخدم يقرأ أو يعدّل بيانات
 *      اتحاد غيره حتى لو عرف معرّفات السجلات.
 *   3) جدول "users" الخام (يحتوي كلمة المرور) لا يُقرأ أبدًا عبر هذا
 *      المسار — القراءة تكون فقط عبر "users_public" التي لا تحتوي العمود.
 *   4) كلمات المرور تُخزَّن مُشفَّرة (bcrypt عبر pgcrypto) وليست نصًا صريحًا.
 *   5) الحقول القابلة للإدخال/التعديل محصورة بقائمة معروفة لكل جدول لمنع
 *      إرسال أعمدة غير متوقعة.
 *   6) محاولات تسجيل الدخول مُقيَّدة بعدد محاولات لكل عنوان IP.
 */
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const compression = require('compression');
const multer = require('multer');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

// خلف بروكسي Render — يلزم لمعرفة عنوان IP الحقيقي للعميل (لتحديد معدل تسجيل الدخول)
app.set('trust proxy', 1);

const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || '';

if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
  console.warn('⚠ تحذير: متغيرات البيئة SUPABASE_URL و SUPABASE_SERVICE_KEY غير معرّفة. أضفهما من Render → Environment.');
}

const supabase = SUPABASE_URL && SUPABASE_SERVICE_KEY
  ? createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, { auth: { persistSession: false } })
  : null;

/* =========================================================================
   رمز الجلسة (Session token) — HMAC موقَّع بمفتاح سرّي على الخادم فقط.
   لا يحتاج مكتبة خارجية (jsonwebtoken)؛ نفس الفكرة بأبسط شكل.
   ========================================================================= */
let SESSION_SECRET = process.env.SESSION_SECRET || '';
if (!SESSION_SECRET) {
  SESSION_SECRET = crypto.randomBytes(48).toString('hex');
  console.warn('⚠ تحذير أمني: متغيّر البيئة SESSION_SECRET غير معرّف. تم توليد مفتاح مؤقت للجلسة —');
  console.warn('  هذا يعني أن كل جلسات الدخول ستُلغى تلقائيًا عند أي إعادة تشغيل للخادم.');
  console.warn('  أضِف SESSION_SECRET (نص عشوائي طويل) في Render → Environment لتفادي ذلك.');
}
const TOKEN_TTL_MS = 12 * 60 * 60 * 1000; // 12 ساعة

function b64url(buf) { return Buffer.from(buf).toString('base64url'); }

function signToken(payloadObj) {
  const payload = b64url(JSON.stringify(payloadObj));
  const sig = b64url(crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest());
  return `${payload}.${sig}`;
}

function verifyToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [payload, sig] = token.split('.');
  const expected = b64url(crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest());
  // مقارنة بزمن ثابت لتفادي هجمات توقيت المقارنة
  const a = Buffer.from(sig || '');
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const obj = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!obj || !obj.uid || !obj.exp || Date.now() > obj.exp) return null;
    return obj;
  } catch (e) {
    return null;
  }
}

/* =========================================================================
   تحديد معدّل محاولات تسجيل الدخول (حماية من التخمين الآلي لكلمة المرور)
   ========================================================================= */
const LOGIN_WINDOW_MS = 10 * 60 * 1000; // 10 دقائق
const LOGIN_MAX_ATTEMPTS = 12;
const loginAttempts = new Map(); // ip -> { count, resetAt }
function checkLoginRateLimit(ip) {
  const now = Date.now();
  const entry = loginAttempts.get(ip);
  if (!entry || now > entry.resetAt) {
    loginAttempts.set(ip, { count: 1, resetAt: now + LOGIN_WINDOW_MS });
    return true;
  }
  entry.count += 1;
  return entry.count <= LOGIN_MAX_ATTEMPTS;
}
// تنظيف دوري بسيط لمنع تضخّم الذاكرة
setInterval(() => {
  const now = Date.now();
  for (const [ip, e] of loginAttempts) if (now > e.resetAt) loginAttempts.delete(ip);
}, 30 * 60 * 1000).unref();

/* =========================================================================
   الجداول المسموحة، والحقول القابلة للإدخال/التعديل لكل جدول، وعمود
   الاتحاد الذي يُستخدم لتقييد الوصول (عزل بيانات كل اتحاد عن غيره).
   ========================================================================= */
const TABLE_FIELDS = {
  federations: ['federation_id', 'federation_name_ar', 'federation_name_en', 'image', 'created_by', 'created_at'],
  users: ['user_id', 'federation_id', 'user_status', 'employee_name_ar', 'employee_name_en', 'national_id', 'nationality', 'phone', 'email', 'user_name', 'password', 'user_type', 'Job_Title', 'language', 'created_at', 'created_by'],
  cost_centers: ['cost_center_id', 'federation_id', 'parent_cost_center_id', 'cost_center_name_ar', 'cost_center_name_en', 'created_by', 'created_at'],
  expense_types: ['account_number', 'expense_name_ar', 'expense_name_en', 'created_at', 'created_by'],
  custodies: ['custody_id', 'federation_id', 'custody_status', 'received_by_user_id', 'custody_type', 'description_ar', 'description_en', 'disbursement_location', 'cost_center_id', 'Opening_balance', 'Custody_balance', 'Closing_date', 'created_by', 'created_at', 'request_approved_by', 'request_approval_date', 'closure_approved_by', 'closure_approval_date', 'Print_Count'],
  custody_closures: ['closure_id', 'federation_id', 'disbursement_status', 'user_id', 'custody_id', 'expense_type_id', 'cost_center_id', 'statement', 'currency', 'foreign_amount', 'exchange_rate', 'amount', 'file', 'entry_location', 'created_by', 'created_at', 'approved_by', 'approved_at'],
  custody_transfers: ['transfer_id', 'federation_id', 'transfer_status', 'user_id', 'custody_id', 'statement', 'currency', 'foreign_amount', 'exchange_rate', 'amount', 'file', 'created_at', 'created_by', 'approved_by', 'approved_at'],
  custody_budgets: ['budget_id', 'Record_Status', 'federation_id', 'custody_id', 'expense_type_id', 'cost_center_id', 'estimated_amount', 'created_by', 'created_at', 'approved_by', 'approved_at'],
  trips: ['trip_id', 'federation_number', 'trip_status', 'trip_name_ar', 'trip_name_en', 'trip_type', 'justifications', 'desired_results', 'achieved_results', 'cost_centers_id', 'start_date', 'end_date', 'trip_days_count', 'entity', 'other_notes', 'has_sports_equipment', 'is_transportation_available', 'is_accommodation_available', 'file', 'Balance_trips', 'created_by', 'created_at', 'request_approved_by', 'request_approval_date', 'closure_approved_by', 'closure_approval_date'],
  delegations: ['delegation_id', 'trip_id', 'federation_number', 'delegations_status', 'user_type', 'user_id', 'amount_delegations', 'is_linked_to_trip', 'justification', 'delegation_days_count', 'start_date', 'end_date', 'is_transportation_available', 'is_accommodation_available', 'achieved_goal', 'hours_count', 'ticket_type', 'is_car_traveler', 'ticket_price', 'total_amount', 'file', 'created_by', 'created_at', 'request_approved_by', 'request_approval_date'],
  other_expenses: ['expense_id', 'trip_id', 'federation_number', 'expense_status', 'expense_type', 'beneficiary', 'justification', 'amount', 'file', 'created_by', 'created_at', 'request_approved_by', 'request_approval_date'],
};
// الجداول القابلة للقراءة فقط عبر هذا المسار (يشمل العرض الآمن users_public)
const READABLE_TABLES = new Set([...Object.keys(TABLE_FIELDS), 'users_public']);
// عمود الاتحاد المستخدم لعزل البيانات لكل جدول (غير موجود = غير مرتبط باتحاد واحد أو معالجته خاصة)
const FED_FIELD = {
  users: 'federation_id', users_public: 'federation_id',
  cost_centers: 'federation_id',
  custodies: 'federation_id', custody_budgets: 'federation_id',
  custody_transfers: 'federation_id', custody_closures: 'federation_id',
  trips: 'federation_number', delegations: 'federation_number', other_expenses: 'federation_number',
};
// جداول لا يُسمح بإدخال/تعديل مباشر فيها من الواجهة إطلاقًا (لا استخدام لها في التطبيق، وأي تعديل عليها حساس جدًا)
const NO_WRITE_TABLES = new Set(['federations']);
const ALLOWED_RPC = new Set(['login', 'change_password']);
// أنواع المستخدمين الممنوعة من تسجيل الدخول إلى أي نظام (سجلات فقط، بلا وصول)
const NO_LOGIN_USER_TYPES = new Set(['لاعب', 'حكم', 'متعاون']);
// أنواع لا يحق لها إدارة المستخدمين (إضافة حسابات جديدة) — يطابق Perm.canManageUsers في الواجهة
const CANNOT_MANAGE_USERS_TYPES = new Set(['موظف', 'موارد بشرية', 'عضو مجلس الادارة']);

function filterFields(obj, allowed) {
  if (!obj || typeof obj !== 'object') return {};
  const out = {};
  for (const k of Object.keys(obj)) if (allowed.includes(k)) out[k] = obj[k];
  return out;
}

/* جلب بيانات المستخدم الحالية من قاعدة البيانات مباشرة (وليس من الرمز نفسه)
   حتى تنعكس أي تغييرات (تعطيل الحساب، تغيير الصلاحية) فورًا على كل طلب جديد. */
async function loadCurrentUser(uid) {
  const { data, error } = await supabase.from('users_public').select('*').eq('user_id', uid).single();
  if (error || !data) return null;
  if (data.user_status !== 'مفتوح') return null;
  if (NO_LOGIN_USER_TYPES.has(data.user_type)) return null;
  return data;
}

const ATTACHMENTS_BUCKET = 'attachments';
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 }, // 8MB
  fileFilter: (req, file, cb) => {
    const ok = /^image\//.test(file.mimetype) || file.mimetype === 'application/pdf';
    cb(ok ? null : new Error('نوع الملف غير مدعوم — يُسمح فقط بالصور أو ملفات PDF'), ok);
  }
});

app.disable('x-powered-by');
app.use(compression());
app.use(express.json({ limit: '2mb' }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

/* -------------------------------------------------------------------
   فحص سريع (بدون كشف بيانات) لعرض تنبيه "لا يوجد مستخدمون بعد" في شاشة
   الدخول الأولى فقط — قبل تسجيل الدخول، بدون الحاجة لرمز جلسة.
   ------------------------------------------------------------------- */
app.get('/api/has-users', async (req, res) => {
  if (!supabase) return res.status(500).json({ hasUsers: true });
  try {
    const { count, error } = await supabase.from('users_public').select('user_id', { count: 'exact', head: true });
    if (error) return res.status(200).json({ hasUsers: true }); // لا نكشف تفاصيل الخطأ هنا
    res.json({ hasUsers: (count || 0) > 0 });
  } catch (e) {
    res.status(200).json({ hasUsers: true });
  }
});

/* -------------------------------------------------------------------
   المسار الوحيد للتواصل مع قاعدة البيانات — بروكسي محكوم ومصادَق عليه
   ------------------------------------------------------------------- */
app.post('/api/db', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (!supabase) {
    return res.status(500).json({ data: null, error: { message: 'الخادم غير مهيّأ بعد: أضف SUPABASE_URL و SUPABASE_SERVICE_KEY في إعدادات البيئة على Render.' } });
  }
  const { op, table, payload, pkField, id, patch, returning, fn, args } = req.body || {};

  /* -------- تسجيل الدخول: العملية الوحيدة المسموحة بدون رمز جلسة -------- */
  if (op === 'rpc' && fn === 'login') {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    if (!checkLoginRateLimit(ip)) {
      return res.status(429).json({ data: null, error: { message: 'محاولات دخول كثيرة جدًا. الرجاء المحاولة لاحقًا.' } });
    }
    try {
      const { data, error } = await supabase.rpc('login', args || {});
      if (error) return res.status(200).json({ data: null, error: { message: error.message } });
      let rows = Array.isArray(data) ? data : [];
      rows = rows.filter(u => !NO_LOGIN_USER_TYPES.has(u.user_type) && u.user_status === 'مفتوح');
      if (!rows.length) return res.json({ data: [], error: null }); // بيانات دخول خاطئة أو حساب غير مفعّل
      const u = rows[0];
      const token = signToken({ uid: u.user_id, iat: Date.now(), exp: Date.now() + TOKEN_TTL_MS });
      return res.json({ data: rows, token, error: null });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ data: null, error: { message: e.message || 'خطأ غير متوقع في الخادم' } });
    }
  }

  /* -------- كل ما عدا تسجيل الدخول يتطلب رمز جلسة صالح -------- */
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
  const claims = verifyToken(token);
  if (!claims) {
    return res.status(401).json({ data: null, error: { message: 'انتهت الجلسة أو غير صالحة. الرجاء تسجيل الدخول من جديد.', code: 'AUTH_REQUIRED' } });
  }
  const currentUser = await loadCurrentUser(claims.uid);
  if (!currentUser) {
    return res.status(401).json({ data: null, error: { message: 'الحساب غير موجود أو غير مفعّل. الرجاء تسجيل الدخول من جديد.', code: 'AUTH_REQUIRED' } });
  }
  const isAuditor = currentUser.user_type === 'مراجع';

  try {
    let query;

    if (op === 'select') {
      if (table === 'users') {
        // القراءة المباشرة لجدول المستخدمين (يحتوي كلمة المرور) ممنوعة تمامًا عبر هذا المسار
        return res.status(403).json({ data: null, error: { message: 'غير مسموح بقراءة هذا الجدول مباشرة.' } });
      }
      if (!READABLE_TABLES.has(table)) return res.status(400).json({ data: null, error: { message: 'جدول غير مسموح: ' + table } });
      query = supabase.from(table).select('*');
      const fedField = FED_FIELD[table];
      if (fedField && !isAuditor) query = query.eq(fedField, currentUser.federation_id);
      if (table === 'federations' && !isAuditor) query = query.eq('federation_id', currentUser.federation_id);

    } else if (op === 'insert') {
      if (!TABLE_FIELDS[table]) return res.status(400).json({ data: null, error: { message: 'جدول غير مسموح: ' + table } });
      if (NO_WRITE_TABLES.has(table)) return res.status(403).json({ data: null, error: { message: 'غير مسموح بالكتابة في هذا الجدول.' } });

      let cleanPayload = filterFields(payload, TABLE_FIELDS[table]);

      if (table === 'users') {
        if (CANNOT_MANAGE_USERS_TYPES.has(currentUser.user_type)) {
          return res.status(403).json({ data: null, error: { message: 'لا تملك صلاحية إضافة مستخدمين.' } });
        }
        if (!cleanPayload.password) {
          return res.status(400).json({ data: null, error: { message: 'كلمة المرور مطلوبة.' } });
        }
        const { data: hashed, error: hashErr } = await supabase.rpc('hash_password', { p: cleanPayload.password });
        if (hashErr) return res.status(500).json({ data: null, error: { message: 'تعذّر تجهيز كلمة المرور.' } });
        cleanPayload.password = hashed;
        if (!isAuditor) cleanPayload.federation_id = currentUser.federation_id;
      } else if (table === 'expense_types') {
        if (!isAuditor) return res.status(403).json({ data: null, error: { message: 'لا تملك صلاحية إضافة نوع مصروف.' } });
      } else {
        const fedField = FED_FIELD[table];
        if (fedField && !isAuditor) cleanPayload[fedField] = currentUser.federation_id;
      }
      if (TABLE_FIELDS[table].includes('created_by')) {
        cleanPayload.created_by = currentUser.user_id;
      }

      query = supabase.from(table).insert(cleanPayload);
      if (returning) query = query.select().single();

    } else if (op === 'update') {
      if (!TABLE_FIELDS[table]) return res.status(400).json({ data: null, error: { message: 'جدول غير مسموح: ' + table } });
      if (NO_WRITE_TABLES.has(table)) return res.status(403).json({ data: null, error: { message: 'غير مسموح بالكتابة في هذا الجدول.' } });
      if (!pkField || !id) return res.status(400).json({ data: null, error: { message: 'معرّف السجل مطلوب للتحديث.' } });

      let cleanPatch = filterFields(patch, TABLE_FIELDS[table]);
      const fedField = FED_FIELD[table];
      if (fedField) delete cleanPatch[fedField]; // لا يجوز نقل سجل لاتحاد آخر عبر التحديث

      if (table === 'users') {
        delete cleanPatch.password; // تغيير كلمة المرور يكون فقط عبر change_password
      }

      query = supabase.from(table).update(cleanPatch).eq(pkField, id);
      if (fedField && !isAuditor) query = query.eq(fedField, currentUser.federation_id);
      if (returning) query = query.select().single();

    } else if (op === 'delete') {
      if (!TABLE_FIELDS[table]) return res.status(400).json({ data: null, error: { message: 'جدول غير مسموح: ' + table } });
      if (NO_WRITE_TABLES.has(table) || table === 'users') return res.status(403).json({ data: null, error: { message: 'غير مسموح بالحذف من هذا الجدول.' } });
      if (!pkField || !id) return res.status(400).json({ data: null, error: { message: 'معرّف السجل مطلوب للحذف.' } });

      query = supabase.from(table).delete().eq(pkField, id);
      const fedFieldDel = FED_FIELD[table];
      if (fedFieldDel && !isAuditor) query = query.eq(fedFieldDel, currentUser.federation_id);

    } else if (op === 'rpc') {
      if (!ALLOWED_RPC.has(fn)) return res.status(400).json({ data: null, error: { message: 'دالة غير مسموحة: ' + fn } });
      const safeArgs = Object.assign({}, args || {});
      if (fn === 'change_password') {
        // يُمنع تغيير كلمة مرور أي حساب آخر حتى لو أرسل العميل معرّفًا مختلفًا
        safeArgs.p_user_id = currentUser.user_id;
      }
      query = supabase.rpc(fn, safeArgs);
    } else {
      return res.status(400).json({ data: null, error: { message: 'عملية غير معروفة: ' + op } });
    }

    const { data, error } = await query;
    if (error) return res.status(200).json({ data: null, error: { message: error.message } });
    if (table === 'users' && data) {
      if (Array.isArray(data)) data.forEach(r => { if (r) delete r.password; });
      else delete data.password;
    }
    res.json({ data, error: null });
  } catch (e) {
    console.error(e);
    res.status(500).json({ data: null, error: { message: e.message || 'خطأ غير متوقع في الخادم' } });
  }
});

app.get('/healthz', (req, res) => res.status(200).send('ok'));

/* -------------------------------------------------------------------
   المرفقات: رفع ملف، وتوليد رابط مؤقت لعرضه — تتطلب أيضًا رمز جلسة صالح
   ------------------------------------------------------------------- */
function requireAuth(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
  const claims = verifyToken(token);
  if (!claims) return res.status(401).json({ data: null, error: { message: 'الرجاء تسجيل الدخول من جديد.', code: 'AUTH_REQUIRED' } });
  req.uid = claims.uid;
  next();
}

app.post('/api/upload', requireAuth, (req, res) => {
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

app.post('/api/file-url', requireAuth, express.json(), async (req, res) => {
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
