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
const nodemailer = require('nodemailer');

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
   إرسال البريد (لميزة "نسيت كلمة المرور") — أربع طرق، اختر واحدة فقط:

   1) RESEND_API_KEY — يحتاج توثيق نطاق (domain) لإرسال فعلي لأي بريد، أو
      يمكن تجربته مباشرة عبر onboarding@resend.dev لبريدك أنت فقط للاختبار.
   2) BREVO_API_KEY — يحتاج توثيق بريد "مُرسل" واحد فقط (أسهل من نطاق كامل).
   3) SENDGRID_API_KEY — نفس مبدأ Brevo تقريبًا (توثيق بريد مُرسل واحد)،
      لكن مزوّد مختلف — بديل جاهز إن تعذّر الوصول لأحد المزوّدين الآخرين.
   4) SMTP_HOST/SMTP_USER/SMTP_PASS — تعمل فقط لو كانت منافذ SMTP الصادرة
      (587/465) غير محجوبة على مضيفك. Render يحجبها افتراضيًا غالبًا، لذا
      الطرق الثلاث أعلاه أضمن بكثير عليه.
   الأولوية عند توفر أكثر من طريقة معًا: Resend، ثم Brevo، ثم SendGrid، ثم SMTP.
   ========================================================================= */
const envTrim = (v) => (v || '').trim();
const RESEND_API_KEY = envTrim(process.env.RESEND_API_KEY);
const RESEND_FROM = envTrim(process.env.RESEND_FROM);
const BREVO_API_KEY = envTrim(process.env.BREVO_API_KEY);
const SENDGRID_API_KEY = envTrim(process.env.SENDGRID_API_KEY);
const SENDGRID_FROM = envTrim(process.env.SENDGRID_FROM) || envTrim(process.env.SMTP_FROM);
const SMTP_HOST = envTrim(process.env.SMTP_HOST);
const SMTP_USER = envTrim(process.env.SMTP_USER);
const SMTP_PASS = envTrim(process.env.SMTP_PASS);
const SMTP_FROM = envTrim(process.env.SMTP_FROM) || SMTP_USER;

let mailTransporter = null;
if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
  mailTransporter = nodemailer.createTransport({
    host: SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: process.env.SMTP_SECURE === 'true',
    auth: { user: SMTP_USER, pass: SMTP_PASS },
    // مهلات صارمة حتى لا يعلّق الطلب دقائق طويلة إن كان المنفذ محجوبًا —
    // يفشل بسرعة برسالة خطأ واضحة بدل التعليق الصامت
    connectionTimeout: 8000,
    greetingTimeout: 8000,
    socketTimeout: 8000,
  });
}
const MAIL_CONFIGURED = !!(RESEND_API_KEY || BREVO_API_KEY || SENDGRID_API_KEY || mailTransporter);
if (!MAIL_CONFIGURED) {
  console.warn('⚠ تحذير: لا توجد إعدادات بريد (لا RESEND_API_KEY ولا BREVO_API_KEY ولا SENDGRID_API_KEY ولا SMTP). ميزة "نسيت كلمة المرور" لن تعمل حتى تُضاف إحداها في Render → Environment.');
} else {
  // تشخيص عند الإقلاع: يطبع المزوّدين المفعّلين وأي خلل واضح في القيم،
  // فتعرف من سجل Render مباشرة سبب أي فشل قبل أن يجربه المستخدمون.
  const on = [];
  if (RESEND_API_KEY) on.push('Resend');
  if (BREVO_API_KEY) on.push('Brevo');
  if (SENDGRID_API_KEY) on.push('SendGrid');
  if (mailTransporter) on.push('SMTP');
  console.log('✉ مزوّدو البريد المفعّلون بالترتيب:', on.join(' ← '));
  if (SENDGRID_API_KEY && !SENDGRID_API_KEY.startsWith('SG.')) {
    console.warn('⚠ SENDGRID_API_KEY لا يبدأ بـ "SG." — الغالب أنه ناقص أو منسوخ خطأً. مفاتيح SendGrid تبدأ دائمًا بـ SG.');
  }
  if (SENDGRID_API_KEY && !SENDGRID_FROM) {
    console.warn('⚠ SENDGRID_API_KEY موجود لكن SENDGRID_FROM غير معرّف — لن يعمل الإرسال عبر SendGrid.');
  }
  if (BREVO_API_KEY && !(envTrim(process.env.BREVO_FROM_EMAIL) || envTrim(process.env.SMTP_FROM))) {
    console.warn('⚠ BREVO_API_KEY موجود لكن BREVO_FROM_EMAIL غير معرّف — لن يعمل الإرسال عبر Brevo.');
  }
}

/* =========================================================================
   طبقة إرسال البريد
   -------------------------------------------------------------------------
   مهم: النسخة السابقة كانت تتوقف عند أول مزوّد "مُعرَّف" فقط — فلو كان مفتاحه
   خاطئًا أو ملغيًا فشل الإرسال كليًا حتى لو كان هناك مزوّد آخر سليم مضبوط.
   الآن نجرّب كل المزوّدين المتاحين بالترتيب، وننتقل للتالي عند الفشل، ولا
   نُرجع خطأ إلا إذا فشلوا جميعًا — مع رسالة تشخيص عربية واضحة تقول بالضبط
   ما الذي يجب إصلاحه في متغيرات البيئة.
   ========================================================================= */

/* ترجمة أخطاء مزوّدي البريد الشائعة إلى سبب واضح وحل عملي */
function explainMailError(provider, status, bodyText) {
  const t = String(bodyText || '');
  if (status === 401) {
    return `${provider}: المفتاح غير صالح أو ملغى (401). أنشئ مفتاح API جديدًا من لوحة ${provider} بصلاحية إرسال البريد (Mail Send / Full Access)، وانسخه كاملاً بدون مسافات أو علامات اقتباس، وضعه في Render → Environment ثم أعد تشغيل الخدمة. ملاحظة: مفتاح ${provider} يُعرض مرة واحدة فقط عند إنشائه.`;
  }
  if (status === 403) {
    return `${provider}: المفتاح صالح لكن بريد المُرسل غير موثّق أو المفتاح لا يملك صلاحية الإرسال (403). وثّق بريد المُرسل (Sender Verification) في لوحة ${provider}، وتأكد أن قيمة بريد المُرسل في متغيرات البيئة تطابقه حرفًا بحرف. التفاصيل: ${t.slice(0, 160)}`;
  }
  if (status === 400 && /from|sender|domain|verif/i.test(t)) {
    return `${provider}: بريد المُرسل مرفوض (400) — غالبًا غير موثّق أو مكتوب بصيغة خاطئة. التفاصيل: ${t.slice(0, 160)}`;
  }
  if (status === 429) return `${provider}: تجاوزت حد الإرسال المسموح مؤقتًا (429). حاول بعد قليل.`;
  return `${provider}: فشل الإرسال (${status}). التفاصيل: ${t.slice(0, 180)}`;
}

async function postJSON(url, headers, body, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs || 10000);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: Object.assign({ 'Content-Type': 'application/json' }, headers),
      body: JSON.stringify(body),
      signal: controller.signal,
    });
    const text = res.ok ? '' : await res.text().catch(() => '');
    return { ok: res.ok, status: res.status, text };
  } finally {
    clearTimeout(timer);
  }
}

/* قائمة المزوّدين المتاحين حسب متغيرات البيئة، بالترتيب المفضّل */
function mailProviders() {
  const list = [];
  if (RESEND_API_KEY) list.push({
    name: 'Resend',
    from: RESEND_FROM || 'onboarding@resend.dev',
    send: async ({ to, subject, text, html }) => postJSON(
      'https://api.resend.com/emails',
      { 'Authorization': `Bearer ${RESEND_API_KEY}` },
      { from: RESEND_FROM || 'onboarding@resend.dev', to: [to], subject, text, html },
    ),
  });
  if (BREVO_API_KEY) {
    const from = envTrim(process.env.BREVO_FROM_EMAIL) || envTrim(process.env.SMTP_FROM);
    list.push({
      name: 'Brevo',
      from,
      missing: from ? null : 'أضف BREVO_FROM_EMAIL (بريد المُرسل الموثّق في Brevo) في متغيرات البيئة.',
      send: async ({ to, subject, text, html }) => postJSON(
        'https://api.brevo.com/v3/smtp/email',
        { 'api-key': BREVO_API_KEY },
        { sender: { email: from }, to: [{ email: to }], subject, textContent: text, htmlContent: html },
      ),
    });
  }
  if (SENDGRID_API_KEY) list.push({
    name: 'SendGrid',
    from: SENDGRID_FROM,
    missing: SENDGRID_FROM ? null : 'أضف SENDGRID_FROM (بريد المُرسل الموثّق في SendGrid) في متغيرات البيئة.',
    send: async ({ to, subject, text, html }) => postJSON(
      'https://api.sendgrid.com/v3/mail/send',
      { 'Authorization': `Bearer ${SENDGRID_API_KEY}` },
      {
        personalizations: [{ to: [{ email: to }] }],
        from: { email: SENDGRID_FROM },
        subject,
        content: [{ type: 'text/plain', value: text }, { type: 'text/html', value: html }],
      },
    ),
  });
  if (mailTransporter) list.push({
    name: 'SMTP',
    from: SMTP_FROM,
    smtp: true,
  });
  return list;
}

/* إرسال موحّد: يجرّب كل مزوّد متاح بالترتيب، وينجح بأول واحد يعمل */
async function sendMailUnified({ to, subject, text, html }) {
  const providers = mailProviders();
  if (!providers.length) throw new Error('لا توجد إعدادات بريد مفعّلة على الخادم. أضِف RESEND_API_KEY أو BREVO_API_KEY أو SENDGRID_API_KEY في Render → Environment.');

  const problems = [];
  for (const p of providers) {
    if (p.missing) { problems.push(p.missing); continue; }
    try {
      if (p.smtp) {
        await mailTransporter.sendMail({ from: SMTP_FROM, to, subject, text, html });
      } else {
        const r = await p.send({ to, subject, text, html });
        if (!r.ok) { problems.push(explainMailError(p.name, r.status, r.text)); continue; }
      }
      if (problems.length) console.warn('تم الإرسال عبر ' + p.name + ' بعد فشل مزوّدين آخرين:', problems.join(' | '));
      return { provider: p.name };
    } catch (e) {
      const msg = (e && e.name === 'AbortError')
        ? `${p.name}: انتهت المهلة قبل استجابة الخادم.`
        : `${p.name}: ${(e && e.message) || 'خطأ غير متوقع'}`;
      problems.push(msg);
    }
  }
  const err = new Error(problems.join(' — '));
  err.mailProblems = problems;
  throw err;
}

function maskEmail(email) {
  const parts = String(email || '').split('@');
  if (parts.length !== 2) return '***';
  const user = parts[0];
  const masked = user.length <= 2 ? user[0] + '*' : user.slice(0, 2) + '*'.repeat(Math.max(1, user.length - 2));
  return masked + '@' + parts[1];
}

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

/* رمز محدود الغرض (purpose token) — نفس آلية توقيع الجلسة، لكن بحقل "purpose"
   إضافي حتى لا يمكن استخدام رمز الجلسة الحقيقي مكان رمز استعادة كلمة المرور
   والعكس، ولا استخدام رمز إحدى مرحلتي الاستعادة مكان الأخرى. */
function signPurposeToken(purpose, payloadObj, ttlMs) {
  return signToken(Object.assign({}, payloadObj, { purpose, exp: Date.now() + ttlMs }));
}
function verifyPurposeToken(token, purpose) {
  const obj = verifyToken(token);
  if (!obj || obj.purpose !== purpose) return null;
  return obj;
}

/* =========================================================================
   تحديد معدّل المحاولات (حماية من التخمين الآلي) — لتسجيل الدخول ولمسارات
   استعادة كلمة المرور عبر المصادقة الثنائية على حدّ سواء.
   ========================================================================= */
const RATE_WINDOW_MS = 10 * 60 * 1000; // 10 دقائق
function makeRateLimiter(maxAttempts, windowMs) {
  const store = new Map(); // ip -> { count, resetAt }
  setInterval(() => {
    const now = Date.now();
    for (const [ip, e] of store) if (now > e.resetAt) store.delete(ip);
  }, 30 * 60 * 1000).unref();
  return function check(ip) {
    const now = Date.now();
    const entry = store.get(ip);
    if (!entry || now > entry.resetAt) {
      store.set(ip, { count: 1, resetAt: now + windowMs });
      return true;
    }
    entry.count += 1;
    return entry.count <= maxAttempts;
  };
}
const checkLoginRateLimit = makeRateLimiter(12, RATE_WINDOW_MS);
// مسارات استعادة كلمة المرور بالمصادقة الثنائية — نفس مبدأ تحديد المعدّل، بحد أعلى أقل
// لأنها عملية حسّاسة (تنتهي بتغيير كلمة المرور)
const checkForgotRateLimit = makeRateLimiter(8, RATE_WINDOW_MS);

/* =========================================================================
   الجداول المسموحة، والحقول القابلة للإدخال/التعديل لكل جدول، وعمود
   الاتحاد الذي يُستخدم لتقييد الوصول (عزل بيانات كل اتحاد عن غيره).
   ========================================================================= */
const TABLE_FIELDS = {
  federations: ['federation_id', 'federation_name_ar', 'federation_name_en', 'image', 'created_by', 'created_at'],
  users: ['user_id', 'federation_id', 'user_status', 'employee_name_ar', 'employee_name_en', 'national_id', 'nationality', 'phone', 'email', 'user_name', 'password', 'user_type', 'Job_Title', 'is_continental_member', 'language', 'created_at', 'created_by'],
  cost_centers: ['cost_center_id', 'federation_id', 'parent_cost_center_id', 'cost_center_name_ar', 'cost_center_name_en', 'created_by', 'created_at'],
  expense_types: ['account_number', 'expense_name_ar', 'expense_name_en', 'created_at', 'created_by'],
  custodies: ['custody_id', 'federation_id', 'custody_status', 'received_by_user_id', 'custody_type', 'description_ar', 'description_en', 'disbursement_location', 'cost_center_id', 'Opening_balance', 'Custody_balance', 'Closing_date', 'created_by', 'created_at', 'request_approved_by', 'request_approval_date', 'closure_approved_by', 'closure_approval_date', 'Print_Count'],
  custody_closures: ['closure_id', 'federation_id', 'disbursement_status', 'user_id', 'custody_id', 'expense_type_id', 'cost_center_id', 'statement', 'currency', 'foreign_amount', 'exchange_rate', 'amount', 'file', 'entry_location', 'created_by', 'created_at', 'approved_by', 'approved_at'],
  custody_transfers: ['transfer_id', 'federation_id', 'transfer_status', 'user_id', 'custody_id', 'statement', 'currency', 'foreign_amount', 'exchange_rate', 'amount', 'file', 'created_at', 'created_by', 'approved_by', 'approved_at'],
  custody_budgets: ['budget_id', 'Record_Status', 'federation_id', 'custody_id', 'expense_type_id', 'cost_center_id', 'estimated_amount', 'created_by', 'created_at', 'approved_by', 'approved_at'],
  trips: ['trip_id', 'federation_number', 'trip_status', 'trip_name_ar', 'trip_name_en', 'trip_type', 'justifications', 'desired_results', 'achieved_results', 'cost_centers_id', 'start_date', 'end_date', 'trip_days_count', 'entity', 'other_notes', 'has_sports_equipment', 'is_transportation_available', 'is_accommodation_available', 'file', 'Balance_trips', 'created_by', 'created_at', 'request_approved_by', 'request_approval_date', 'closure_approved_by', 'closure_approval_date'],
  delegations: ['delegation_id', 'trip_id', 'federation_number', 'delegations_status', 'user_type', 'role_task', 'limit_flag', 'limit_note', 'user_id', 'amount_delegations', 'is_linked_to_trip', 'justification', 'delegation_days_count', 'start_date', 'end_date', 'is_transportation_available', 'is_accommodation_available', 'achieved_goal', 'hours_count', 'ticket_type', 'is_car_traveler', 'ticket_price', 'total_amount', 'file', 'created_by', 'created_at', 'request_approved_by', 'request_approval_date'],
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
const NO_LOGIN_USER_TYPES = new Set(['لاعب', 'مرافق لاعب', 'حكم', 'متعاون']);
// أنواع لا يحق لها إدارة المستخدمين (إضافة حسابات جديدة) — يطابق Perm.canManageUsers في الواجهة
const CANNOT_MANAGE_USERS_TYPES = new Set(['موظف', 'موارد بشرية', 'عضو مجلس الادارة', 'رئيس مجلس الادارة']);
/* أنواع لا يعدّل بياناتها (المسمى الوظيفي/نوع المستخدم) ولا يغيّر حالة
   حساباتها (تفعيلها) إلا مراجع اللجنة حصرًا — يطابق PROTECTED_USER_TYPES
   في index.html و secondments.html. */
const PROTECTED_USER_TYPES = new Set(['مدير اللجنة', 'مراجع', 'رئيس الاتحاد', 'مدير تنفيذي', 'رئيس مجلس الادارة', 'عضو مجلس الادارة']);
/* أنواع لجنة الإشراف — نطاق رؤيتها كل الاتحادات، ولا يعيّنها إلا مدير اللجنة */
const SUPERVISOR_TYPES = new Set(['مراجع', 'مدير اللجنة']);
const COMMITTEE_TYPES = new Set(['مدير اللجنة', 'مراجع']);


/* =========================================================================
   تقييد نطاق القراءة: فترة زمنية، أو قائمة معرّفات أب، أو حالات محددة.
   الهدف: ألا تُحمّل الواجهة كل صفوف الجدول عند فتح البرنامج (قد تصل لملايين
   الصفوف)، بل الفترة المختارة فقط.
   ========================================================================= */
const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}(T[\d:.]+Z?)?$/;
function isValidField(table, field) {
  const fields = TABLE_FIELDS[table] || (table === 'users_public' ? TABLE_FIELDS.users : []) || [];
  return typeof field === 'string' && fields.includes(field);
}
function applyScope(query, table, scope) {
  const { dateField, dateFallbackField, dateFrom, dateTo, inField, inValues, statusField, statusValues } = scope;

  // 1) الفترة الزمنية
  if (dateField && isValidField(table, dateField) && (dateFrom || dateTo)) {
    const from = (dateFrom && ISO_DATE_RE.test(dateFrom)) ? dateFrom : null;
    // نهاية الفترة تشمل اليوم المحدد كاملاً: نستخدم "أصغر من اليوم التالي"
    // ليعمل الأمر بشكل صحيح مع أعمدة التاريخ وأعمدة الوقت (timestamp) معًا.
    let to = null;
    if (dateTo && ISO_DATE_RE.test(dateTo)) {
      const d = new Date(dateTo.slice(0, 10) + 'T00:00:00Z');
      d.setUTCDate(d.getUTCDate() + 1);
      to = d.toISOString().slice(0, 10);
    }
    const hasFallback = dateFallbackField && isValidField(table, dateFallbackField);
    if (hasFallback) {
      // العمود الأساسي داخل الفترة، أو (كان فارغًا وعمود الاحتياط داخل الفترة)
      const main = [];
      if (from) main.push(`${dateField}.gte.${from}`);
      if (to) main.push(`${dateField}.lt.${to}`);
      const fb = [`${dateField}.is.null`];
      if (from) fb.push(`${dateFallbackField}.gte.${from}`);
      if (to) fb.push(`${dateFallbackField}.lt.${to}`);
      query = query.or(`and(${main.join(',')}),and(${fb.join(',')})`);
    } else {
      if (from) query = query.gte(dateField, from);
      if (to) query = query.lt(dateField, to);
    }
  }

  // 2) الأبناء التابعون لسجلات أب محمّلة أصلاً (مثل بنود عهدة أو مشاركي رحلة)
  if (inField && isValidField(table, inField) && Array.isArray(inValues)) {
    const vals = inValues.filter(v => typeof v === 'string' || typeof v === 'number').slice(0, 1000);
    if (vals.length === 0) return query.eq(inField, '__none__'); // لا آباء = لا أبناء
    query = query.in(inField, vals);
  }

  // 3) حالات محددة (مثل: العهد المفتوحة فقط، مهما كان تاريخها)
  if (statusField && isValidField(table, statusField) && Array.isArray(statusValues) && statusValues.length) {
    query = query.in(statusField, statusValues.filter(v => typeof v === 'string').slice(0, 20));
  }

  return query;
}

/* =========================================================================
   إنشاء كلمة مرور أولية قوية وإرسالها للمستخدم الجديد على بريده.
   الفلسفة: لا أحد — ولا حتى من أضاف الحساب — يرى كلمة المرور. تُولَّد على
   الخادم، تُشفَّر قبل الحفظ، وتُرسل لصاحبها فقط، ثم يغيّرها من حسابه.
   ========================================================================= */
const PWD_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789';
function generatePassword(len = 12) {
  let out = '';
  for (let i = 0; i < len; i++) out += PWD_ALPHABET[crypto.randomInt(0, PWD_ALPHABET.length)];
  // نضمن وجود رمز خاص ورقم وحرف كبير حتى تجتاز أي سياسة تعقيد
  return out.slice(0, len - 3) + '@' + crypto.randomInt(0, 10) + 'A';
}

async function sendWelcomeMail({ to, name, username, password, federationName }) {
  const subject = 'بيانات الدخول إلى نظام إدارة العهد والانتدابات';
  const text = `مرحبًا ${name || ''}\n\nتم إنشاء حساب لك${federationName ? ' في ' + federationName : ''}.\n\n`
    + `اسم المستخدم: ${username}\nكلمة المرور المؤقتة: ${password}\n\n`
    + `الحساب بحالة "تحت المعالجة" حتى يعتمده رئيس الاتحاد أو المدير التنفيذي.\n`
    + `للأمان: غيّر كلمة المرور من صفحة "حسابي" بعد أول دخول، ولا تشاركها مع أحد.`;
  const html = `<div dir="rtl" style="font-family:Tahoma,Arial,sans-serif;line-height:1.9;">
    <p>مرحبًا ${name || ''}،</p>
    <p>تم إنشاء حساب لك${federationName ? ' في <b>' + federationName + '</b>' : ''} على نظام إدارة العهد النقدية والانتدابات.</p>
    <table style="border-collapse:collapse;margin:14px 0;">
      <tr><td style="padding:6px 12px;background:#f3f5f2;">اسم المستخدم</td><td style="padding:6px 12px;font-weight:bold;">${username}</td></tr>
      <tr><td style="padding:6px 12px;background:#f3f5f2;">كلمة المرور المؤقتة</td><td style="padding:6px 12px;font-weight:bold;letter-spacing:2px;">${password}</td></tr>
    </table>
    <p>الحساب بحالة <b>تحت المعالجة</b> حتى يعتمده رئيس الاتحاد أو المدير التنفيذي.</p>
    <p style="color:#a33;">للأمان: غيّر كلمة المرور من صفحة "حسابي" بعد أول دخول، ولا تشاركها مع أحد.</p>
  </div>`;
  return sendMailUnified({ to, subject, text, html });
}

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

/* يتحقق من رمز الجلسة في رأس الطلب ويُرجع بيانات المستخدم الحالية، أو null إن كانت غير صالحة */
async function authenticateRequest(req) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
  const claims = verifyToken(token);
  if (!claims) return null;
  return await loadCurrentUser(claims.uid);
}

/* -------------------------------------------------------------------
   سجل التدقيق — يسجّل كل محاولة إجراء حسّاس (اعتماد/رفض/إقفال/تغيير حالة)
   سواء نجحت أو فشلت. لا يُفشل الطلب الأصلي أبدًا حتى لو تعذّر التسجيل.
   ------------------------------------------------------------------- */
async function logAudit({ user, action, success, targetTable, targetId, message, ip }) {
  try {
    await supabase.from('audit_log').insert({
      user_id: user ? user.user_id : null,
      user_name: user ? (user.employee_name_ar || user.user_name) : null,
      federation_id: user ? user.federation_id : null,
      action, success,
      target_table: targetTable || null,
      target_id: targetId || null,
      message: message || null,
      ip: ip || null,
    });
  } catch (e) {
    console.error('تعذّر تسجيل سجل التدقيق:', e.message || e);
  }
}

/* خطأ يحمل رمز حالة HTTP مناسب، يُستخدم داخل معالجات الإجراءات */
class ActionError extends Error {
  constructor(message, status) { super(message); this.status = status || 400; }
}

/* ---------------------------- نسخة خادم من منطق الصلاحيات (Perm) ----------------------------
   يجب أن تطابق تمامًا منطق كائن Perm في index.html و secondments.html — أي تعديل هناك
   يلزمه تعديل مقابل هنا. */
const SPerm = {
  /* مدير اللجنة ومراجع اللجنة: نفس نطاق الإشراف على كل الاتحادات.
     ينفرد مدير اللجنة بإضافة المراجعين واعتماد سفر مجلس الإدارة المتجاوز. */
  isCommitteeManager: u => u && u.user_type === 'مدير اللجنة',
  isAuditor: u => u && (u.user_type === 'مراجع' || u.user_type === 'مدير اللجنة'),
  isPresident: u => u && u.user_type === 'رئيس الاتحاد',
  isExec: u => u && u.user_type === 'مدير تنفيذي',
  isAccountant: u => u && u.user_type === 'محاسب',
  isEmployee: u => u && u.user_type === 'موظف',
  isHR: u => u && u.user_type === 'موارد بشرية',
  isBoardChair: u => u && u.user_type === 'رئيس مجلس الادارة',
  // رئيس مجلس الإدارة له نفس صلاحيات عضو مجلس الإدارة تمامًا
  isBoardMember: u => u && (u.user_type === 'عضو مجلس الادارة' || u.user_type === 'رئيس مجلس الادارة'),
  isBasicStaff: u => SPerm.isEmployee(u) || SPerm.isHR(u),
  isTopApprover: u => SPerm.isPresident(u) || SPerm.isExec(u),
};


/* =========================================================================
   ضوابط سفر رئيس وأعضاء مجلس الإدارة — نسخة الخادم.
   يجب أن تطابق تمامًا evaluateBoardTravel في secondments.html.
   الواجهة تحسب العلامة للعرض، لكن الخادم يعيد حسابها دائمًا ويكتبها بنفسه،
   فلا يستطيع أي عميل تزييف علامة \"ضمن الضوابط\" لتفادي اعتماد مدير اللجنة.
   ========================================================================= */
const BOARD_TRAVEL_LIMITS = {
  chairMaxDaysPerTrip: 9,
  chairMaxDaysPerYear: 30,
  chairMaxDaysPerYearContinental: 40,
  chairMaxTripsPerYear: 4,
  chairMaxTripsPerYearContinental: 6,
  memberDomesticQuota: { 'بطولة': 1, 'معسكر': 1 },
  memberForeignTripsIfContinental: 2,
};
const LIMIT_FLAG_OVER = 'تجاوز';
const LIMIT_FLAG_AT = 'عند الحد';

function delegationYearOf(d, trip) {
  const src = (d && d.start_date) || (trip && trip.start_date) || (d && d.created_at) || '';
  return String(src).slice(0, 4);
}

/* يحسب علامة الضوابط لمشاركة جديدة. يعيد { flag, note } */
async function computeBoardLimit(payload, trip) {
  const empty = { flag: null, note: null };
  if (!trip || !payload.user_id) return empty;
  const target = await getRow('users_public', 'user_id', payload.user_id);
  if (!target) return empty;
  const isChair = target.user_type === 'رئيس مجلس الادارة';
  const isMember = target.user_type === 'عضو مجلس الادارة';
  if (!isChair && !isMember) return empty;

  const L = BOARD_TRAVEL_LIMITS;
  const fedId = trip.federation_number;
  const year = delegationYearOf(payload, trip);
  const cont = !!target.is_continental_member;
  const days = Number(payload.delegation_days_count || 0);

  // كل انتدابات ورحلات الاتحاد (المرفوض لا يُحتسب)
  const allDelegations = (await getRows('delegations', { federation_number: fedId }))
    .filter(d => d.delegations_status !== 'مرفوض');
  const allTrips = await getRows('trips', { federation_number: fedId });
  const tripById = id => allTrips.find(t => t.trip_id === id) || null;
  const inYear = d => delegationYearOf(d, tripById(d.trip_id)) === year;

  const notes = [];
  let level = 'ok';
  const mark = (lvl, note) => { notes.push(note); if (lvl === 'over') level = 'over'; else if (level !== 'over') level = 'at'; };

  // ذاكرة مؤقتة لمستخدمي الاتحاد (نوع كل مشارك وعضويته القارية)
  const memberCache = new Map();
  for (const usr of await getRows('users_public', { federation_id: fedId })) memberCache.set(usr.user_id, usr);

  const chair = Array.from(memberCache.values()).find(x => x.user_type === 'رئيس مجلس الادارة') || null;
  const chairTripsLimit = (chair && chair.is_continental_member) ? L.chairMaxTripsPerYearContinental : L.chairMaxTripsPerYear;
  const chairTripsUsed = () => {
    let count = chair ? allDelegations.filter(d => d.user_id === chair.user_id && inYear(d)).length : 0;
    // الرحلات الخارجية لأعضاء المجلس الأعضاء في اتحاد قاري تُخصم من رصيد الرئيس
    for (const d of allDelegations) {
      if (!inYear(d)) continue;
      const t = tripById(d.trip_id);
      if (!t || t.entity === 'المملكة') continue;
      const usr = memberCache.get(d.user_id);
      if (!usr || usr.user_type !== 'عضو مجلس الادارة' || !usr.is_continental_member) continue;
      count++;
    }
    return count;
  };
  if (isChair) {
    if (days > L.chairMaxDaysPerTrip) mark('over', `مدة الرحلة ${days} يومًا وتتجاوز حد ${L.chairMaxDaysPerTrip} أيام للرحلة الواحدة`);
    else if (days === L.chairMaxDaysPerTrip) mark('at', `مدة الرحلة بلغت الحد الأعلى ${L.chairMaxDaysPerTrip} أيام للرحلة الواحدة`);

    const maxDays = cont ? L.chairMaxDaysPerYearContinental : L.chairMaxDaysPerYear;
    const usedDays = allDelegations.filter(d => d.user_id === target.user_id && inYear(d))
      .reduce((sum, x) => sum + Number(x.delegation_days_count || 0), 0);
    const newDays = usedDays + days;
    if (newDays > maxDays) mark('over', `إجمالي أيام السفر يصبح ${newDays} يومًا خلال ${year} ويتجاوز الحد السنوي ${maxDays} يومًا`);
    else if (newDays === maxDays) mark('at', `إجمالي أيام السفر يبلغ الحد السنوي ${maxDays} يومًا خلال ${year}`);

    const maxTrips = cont ? L.chairMaxTripsPerYearContinental : L.chairMaxTripsPerYear;
    const newTrips = chairTripsUsed() + 1;
    if (newTrips > maxTrips) mark('over', `عدد الرحلات يصبح ${newTrips} خلال ${year} ويتجاوز الحد السنوي ${maxTrips} رحلات`);
    else if (newTrips === maxTrips) mark('at', `عدد الرحلات يبلغ الحد السنوي ${maxTrips} رحلات خلال ${year}`);
  } else {
    const own = allDelegations.filter(d => d.user_id === target.user_id && inYear(d));
    if (trip.entity === 'المملكة') {
      const quota = L.memberDomesticQuota[trip.trip_type];
      if (!quota) {
        mark('over', `داخل المملكة يُسمح لعضو مجلس الإدارة برحلة بطولة واحدة ورحلة معسكر واحدة فقط سنويًا — ونوع هذه الرحلة \u201c${trip.trip_type || '—'}\u201d`);
      } else {
        const used = own.filter(x => { const t = tripById(x.trip_id); return t && t.entity === 'المملكة' && t.trip_type === trip.trip_type; }).length;
        if (used + 1 > quota) mark('over', `سبق للعضو ${used} رحلة ${trip.trip_type} داخل المملكة خلال ${year}، والمسموح ${quota} فقط`);
        else mark('at', `هذه رحلة ${trip.trip_type} رقم ${used + 1} من ${quota} المسموح بها داخل المملكة خلال ${year}`);
      }
    } else if (!cont) {
      mark('over', 'السفر خارج المملكة غير مسموح لعضو مجلس الإدارة ما لم يكن عضوًا في اتحاد قاري');
    } else {
      const usedForeign = own.filter(x => { const t = tripById(x.trip_id); return t && t.entity !== 'المملكة'; }).length;
      const newForeign = usedForeign + 1;
      if (newForeign > L.memberForeignTripsIfContinental) mark('over', `العضو استنفد رحلتيه الخارجيتين خلال ${year} (هذه رقم ${newForeign})`);
      else if (newForeign === L.memberForeignTripsIfContinental) mark('at', `هذه الرحلة الخارجية رقم ${newForeign} من ${L.memberForeignTripsIfContinental} المسموح بها خلال ${year}`);

      const chairNew = chairTripsUsed() + 1;
      if (chairNew > chairTripsLimit) mark('over', `تُخصم هذه الرحلة من رصيد رحلات رئيس مجلس الإدارة وقد تجاوز الرصيد (${chairNew} من ${chairTripsLimit})`);
      else if (chairNew === chairTripsLimit) mark('at', `تُخصم من رصيد رحلات رئيس مجلس الإدارة وتبلغ به الحد السنوي (${chairNew} من ${chairTripsLimit})`);
    }
  }

  if (level === 'ok') return empty;
  return { flag: level === 'over' ? LIMIT_FLAG_OVER : LIMIT_FLAG_AT, note: notes.join(' — ') || null };
}

async function getRow(table, pkField, id) {
  const { data, error } = await supabase.from(table).select('*').eq(pkField, id).single();
  if (error || !data) return null;
  return data;
}
async function getRows(table, filters) {
  let q = supabase.from(table).select('*');
  for (const [k, v] of Object.entries(filters)) q = q.eq(k, v);
  const { data, error } = await q;
  if (error) return [];
  return data || [];
}
async function updateRow(table, pkField, id, patch) {
  const { error } = await supabase.from(table).update(patch).eq(pkField, id);
  if (error) throw new ActionError(error.message, 500);
}
async function insertRow(table, payload) {
  const { data, error } = await supabase.from(table).insert(payload).select().single();
  if (error) throw new ActionError(error.message, 500);
  return data;
}
const nowISO = () => new Date().toISOString();

/* -------- منطق العهد: يطابق custodyFinancials في index.html تمامًا -------- */
function computeCustodyFinancials(c, budgets, transfers, expenses) {
  const approvedBudget = budgets.filter(b => b.Record_Status === 'معتمد').reduce((s, b) => s + Number(b.estimated_amount || 0), 0);
  const pendingBudgetLines = budgets.filter(b => b.Record_Status === 'قيد الاعتماد');
  const totalTransferred = transfers.reduce((s, t) => s + Number(t.amount || 0), 0);
  const approvedExpenses = expenses.filter(e => e.disbursement_status === 'معتمد').reduce((s, e) => s + Number(e.amount || 0), 0);
  const pendingExpenses = expenses.filter(e => e.disbursement_status === 'غير معتمد').reduce((s, e) => s + Number(e.amount || 0), 0);
  const pendingExpenseCount = expenses.filter(e => e.disbursement_status === 'غير معتمد').length;
  const opening = Number(c.Opening_balance || 0);
  const fundsAvailable = opening + totalTransferred;
  const remainingBalance = fundsAvailable - approvedExpenses;
  const availableToSpend = remainingBalance - pendingExpenses;
  const pendingTransfer = Math.max(0, approvedBudget - fundsAvailable);
  return { approvedBudget, pendingBudgetLines, totalTransferred, approvedExpenses, pendingExpenses, pendingExpenseCount, fundsAvailable, remainingBalance, availableToSpend, pendingTransfer };
}
/* لو صاحب العهدة رئيس الاتحاد أو المدير التنفيذي، يعتمد/يقفل طرف آخر مستقل تجنبًا لتعارض المصالح */
function requiredApproverOverride(holder) {
  if (!holder) return null;
  if (holder.user_type === 'مدير تنفيذي') return 'isPresident';
  if (holder.user_type === 'رئيس الاتحاد') return 'isExec';
  return null;
}
function overrideAllows(ov, user) {
  if (ov === 'isPresident') return SPerm.isPresident(user);
  if (ov === 'isExec') return SPerm.isExec(user);
  return null; // لا يوجد تعارض مصالح
}
/* لو المشارك بالانتداب نفسه رئيس الاتحاد أو المدير التنفيذي، يوافق عليه الطرف الآخر حصرًا */
function canApproveParticipantRecord(user, participant, participantUser) {
  /* المتجاوز لضوابط سفر مجلس الإدارة: مدير اللجنة وحده يعتمد سفره */
  if (participant && participant.limit_flag === 'تجاوز') return SPerm.isCommitteeManager(user);
  if (SPerm.isCommitteeManager(user)) return true;
  if (!SPerm.isTopApprover(user)) return false;
  const pType = participantUser ? participantUser.user_type : participant.user_type;
  if (pType === 'رئيس الاتحاد') return SPerm.isExec(user);
  if (pType === 'مدير تنفيذي') return SPerm.isPresident(user);
  return true;
}
/* لو المستفيد من مصروف آخر هو رئيس الاتحاد أو المدير التنفيذي، يعتمدها الطرف الآخر حصرًا */
function canApproveOtherExpenseFor(user, expense) {
  const bens = expense && expense.beneficiary ? expense.beneficiary.split(/[،,]\s*/) : [];
  const hasExec = bens.includes('مدير تنفيذي');
  const hasPres = bens.includes('رئيس الاتحاد');
  if (hasExec && !hasPres) return SPerm.isPresident(user);
  if (hasPres && !hasExec) return SPerm.isExec(user);
  return SPerm.isTopApprover(user);
}
const USER_STATUS_VALUES = new Set(['مفتوح', 'مغلق', 'تحت المعالجة', 'مسودة']);

/* =========================================================================
   سجل الإجراءات الحسّاسة — كل واحد منها يُعيد التحقق الكامل من الصلاحية على
   الخادم مباشرة (وليس فقط بالواجهة)، باستخدام بيانات المستخدم المُتحقَّقة من
   الجلسة، ويفرض القيم الحسّاسة (approved_by/created_by...) من الخادم دائمًا.
   ========================================================================= */
const ACTIONS = {

  async approveCustodyRequest({ user }, { custodyId }) {
    const c = await getRow('custodies', 'custody_id', custodyId);
    if (!c || c.federation_id !== user.federation_id) throw new ActionError('العهدة غير موجودة', 404);
    if (c.custody_status !== 'قيد الاعتماد') throw new ActionError('العهدة ليست بانتظار الاعتماد', 400);
    const holder = c.received_by_user_id ? await getRow('users_public', 'user_id', c.received_by_user_id) : null;
    const ov = requiredApproverOverride(holder);
    const allowed = ov ? overrideAllows(ov, user) : SPerm.isTopApprover(user);
    if (!allowed) throw new ActionError(ov ? `لا تملك صلاحية الاعتماد — هذه العهدة تتطلب اعتماد ${ov === 'isPresident' ? 'رئيس الاتحاد' : 'المدير التنفيذي'} تجنبًا لتعارض المصالح` : 'لا تملك صلاحية الاعتماد', 403);
    const budgets = await getRows('custody_budgets', { custody_id: custodyId });
    if (!budgets.length) throw new ActionError('لا يمكن الاعتماد قبل إضافة مصاريف تقديرية', 400);
    await updateRow('custodies', 'custody_id', custodyId, { custody_status: 'مفتوحة', request_approved_by: user.user_id, request_approval_date: nowISO() });
    for (const b of budgets) {
      if (b.Record_Status === 'قيد الاعتماد') {
        await updateRow('custody_budgets', 'budget_id', b.budget_id, { Record_Status: 'معتمد', approved_by: user.user_id, approved_at: nowISO() });
      }
    }
    return { targetTable: 'custodies', targetId: custodyId, message: 'تم اعتماد طلب العهدة' };
  },

  async rejectCustodyRequest({ user }, { custodyId }) {
    const c = await getRow('custodies', 'custody_id', custodyId);
    if (!c || c.federation_id !== user.federation_id) throw new ActionError('العهدة غير موجودة', 404);
    if (c.custody_status !== 'قيد الاعتماد') throw new ActionError('العهدة ليست بانتظار الاعتماد', 400);
    const holder = c.received_by_user_id ? await getRow('users_public', 'user_id', c.received_by_user_id) : null;
    const ov = requiredApproverOverride(holder);
    const allowed = ov ? overrideAllows(ov, user) : SPerm.isTopApprover(user);
    if (!allowed) throw new ActionError('لا تملك صلاحية الرفض', 403);
    await updateRow('custodies', 'custody_id', custodyId, { custody_status: 'مرفوضة', request_approved_by: user.user_id, request_approval_date: nowISO() });
    return { targetTable: 'custodies', targetId: custodyId, message: 'تم رفض طلب العهدة' };
  },

  async approveBudgetLine({ user }, { custodyId, budgetId }) {
    const c = await getRow('custodies', 'custody_id', custodyId);
    if (!c || c.federation_id !== user.federation_id) throw new ActionError('العهدة غير موجودة', 404);
    const holder = c.received_by_user_id ? await getRow('users_public', 'user_id', c.received_by_user_id) : null;
    const ov = requiredApproverOverride(holder);
    const allowed = ov ? overrideAllows(ov, user) : SPerm.isTopApprover(user);
    if (!allowed) throw new ActionError('لا تملك صلاحية اعتماد بند المصروف التقديري', 403);
    if (c.custody_status !== 'مفتوحة') throw new ActionError('لا يمكن اعتماد بند إلا لعهدة مفتوحة', 400);
    const b = await getRow('custody_budgets', 'budget_id', budgetId);
    if (!b || b.custody_id !== custodyId) throw new ActionError('البند غير موجود', 404);
    if (b.Record_Status === 'معتمد') throw new ActionError('البند معتمد بالفعل', 400);
    await updateRow('custody_budgets', 'budget_id', budgetId, { Record_Status: 'معتمد', approved_by: user.user_id, approved_at: nowISO() });
    return { targetTable: 'custody_budgets', targetId: budgetId, message: 'تم اعتماد بند المصروف التقديري' };
  },

  async cancelBudgetLine({ user }, { custodyId, budgetId }) {
    const c = await getRow('custodies', 'custody_id', custodyId);
    if (!c || c.federation_id !== user.federation_id) throw new ActionError('العهدة غير موجودة', 404);
    const holder = c.received_by_user_id ? await getRow('users_public', 'user_id', c.received_by_user_id) : null;
    const ov = requiredApproverOverride(holder);
    const allowed = ov ? overrideAllows(ov, user) : SPerm.isTopApprover(user);
    if (!allowed) throw new ActionError('لا تملك صلاحية إلغاء بند المصروف التقديري', 403);
    const b = await getRow('custody_budgets', 'budget_id', budgetId);
    if (!b || b.custody_id !== custodyId || b.Record_Status !== 'قيد الاعتماد') throw new ActionError('لا يمكن إلغاء هذا البند', 400);
    await updateRow('custody_budgets', 'budget_id', budgetId, { Record_Status: 'ملغى' });
    return { targetTable: 'custody_budgets', targetId: budgetId, message: 'تم إلغاء البند' };
  },

  async saveTransfer({ user }, { custodyId, amount, currency, note, filePath }) {
    if (!SPerm.isAccountant(user)) throw new ActionError('لا تملك صلاحية التحويل', 403);
    const c = await getRow('custodies', 'custody_id', custodyId);
    if (!c || c.federation_id !== user.federation_id) throw new ActionError('العهدة غير موجودة', 404);
    if (c.custody_status !== 'مفتوحة') throw new ActionError('لا يمكن التحويل إلا لعهدة مفتوحة', 400);
    if (user.user_id === c.request_approved_by) throw new ActionError('لا يمكن لمعتمد طلب العهدة تنفيذ التحويل', 403);
    const amt = Number(amount);
    if (!amt || amt <= 0) throw new ActionError('أدخل مبلغًا صحيحًا', 400);
    if (!filePath) throw new ActionError('يجب إرفاق صورة أو ملف PDF لإثبات التحويل', 400);
    const budgets = await getRows('custody_budgets', { custody_id: custodyId });
    const transfers = await getRows('custody_transfers', { custody_id: custodyId });
    const f = computeCustodyFinancials(c, budgets, transfers, []);
    if (amt > f.pendingTransfer + 0.009) throw new ActionError('المبلغ يتجاوز المصاريف التقديرية المعتمدة', 400);
    const cur = currency || 'SAR';
    const saved = await insertRow('custody_transfers', {
      transfer_id: 'trf_' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8),
      federation_id: c.federation_id, transfer_status: 'مكتمل', user_id: c.received_by_user_id,
      custody_id: custodyId, statement: note || '', currency: cur, foreign_amount: cur === 'SAR' ? null : amt, exchange_rate: 1,
      amount: amt, file: filePath, created_at: nowISO(), created_by: user.user_id, approved_by: user.user_id, approved_at: nowISO(),
    });
    const newBalance = Number(c.Custody_balance || 0) + amt;
    await updateRow('custodies', 'custody_id', custodyId, { Custody_balance: newBalance });
    return { targetTable: 'custody_transfers', targetId: saved.transfer_id, message: 'تم تنفيذ التحويل بنجاح', data: saved };
  },

  async approveExpense({ user }, { custodyId, closureId }) {
    const c = await getRow('custodies', 'custody_id', custodyId);
    if (!c || c.federation_id !== user.federation_id) throw new ActionError('العهدة غير موجودة', 404);
    const holder = c.received_by_user_id ? await getRow('users_public', 'user_id', c.received_by_user_id) : null;
    const ov = requiredApproverOverride(holder);
    let allowed;
    if (ov) allowed = overrideAllows(ov, user);
    else if (SPerm.isAccountant(user) && user.user_id === c.received_by_user_id) allowed = SPerm.isExec(user);
    else allowed = SPerm.isAccountant(user) || SPerm.isExec(user);
    if (!allowed) throw new ActionError('لا تملك صلاحية اعتماد المصروف', 403);
    const e = await getRow('custody_closures', 'closure_id', closureId);
    if (!e || e.custody_id !== custodyId) throw new ActionError('المصروف غير موجود', 404);
    if (e.disbursement_status !== 'غير معتمد') throw new ActionError('المصروف تمت معالجته بالفعل', 400);
    await updateRow('custody_closures', 'closure_id', closureId, { disbursement_status: 'معتمد', approved_by: user.user_id, approved_at: nowISO() });
    return { targetTable: 'custody_closures', targetId: closureId, message: 'تم اعتماد المصروف' };
  },

  async closeCustody({ user }, { custodyId }) {
    const c = await getRow('custodies', 'custody_id', custodyId);
    if (!c || c.federation_id !== user.federation_id) throw new ActionError('العهدة غير موجودة', 404);
    const holder = c.received_by_user_id ? await getRow('users_public', 'user_id', c.received_by_user_id) : null;
    const ov = requiredApproverOverride(holder);
    const allowed = ov ? overrideAllows(ov, user) : SPerm.isTopApprover(user);
    if (!allowed) throw new ActionError('لا تملك صلاحية إقفال العهدة', 403);
    const budgets = await getRows('custody_budgets', { custody_id: custodyId });
    const transfers = await getRows('custody_transfers', { custody_id: custodyId });
    const expenses = await getRows('custody_closures', { custody_id: custodyId });
    const f = computeCustodyFinancials(c, budgets, transfers, expenses);
    if (!(f.remainingBalance === 0 && f.pendingExpenseCount === 0 && f.approvedExpenses > 0)) throw new ActionError('لا يمكن إقفال العهدة قبل تسوية الرصيد بالكامل', 400);
    if (f.pendingBudgetLines.length > 0) throw new ActionError('لا يمكن الإقفال قبل اعتماد أو إلغاء كل بنود المصاريف التقديرية المعلّقة', 400);
    await updateRow('custodies', 'custody_id', custodyId, { custody_status: 'مغلقة', Closing_date: nowISO(), closure_approved_by: user.user_id, closure_approval_date: nowISO() });
    return { targetTable: 'custodies', targetId: custodyId, message: 'تم إقفال العهدة بنجاح' };
  },

  async changeUserStatus({ user }, { userId, newStatus }) {
    // المراجع يملك إشرافًا على كل الاتحادات، فيغيّر حالة أي مستخدم؛ وغيره
    // من أصحاب الصلاحية (رئيس الاتحاد/المدير التنفيذي) داخل اتحاده فقط.
    if (!SPerm.isTopApprover(user) && !SPerm.isAuditor(user)) throw new ActionError('لا تملك صلاحية تغيير الحالة', 403);
    if (!USER_STATUS_VALUES.has(newStatus)) throw new ActionError('حالة غير صالحة', 400);
    const target = await getRow('users_public', 'user_id', userId);
    if (!target) throw new ActionError('المستخدم غير موجود', 404);
    if (!SPerm.isAuditor(user) && target.federation_id !== user.federation_id) throw new ActionError('المستخدم غير موجود', 404);
    if (target.user_id === user.user_id) throw new ActionError('لا يمكنك تغيير حالة حسابك أنت', 403);
    // (رئيس الاتحاد / المدير التنفيذي / رئيس مجلس الإدارة / عضو مجلس الإدارة):
    // تفعيل حساباتهم أو تغيير حالتها من صلاحية مراجع اللجنة حصرًا.
    if (PROTECTED_USER_TYPES.has(target.user_type) && !SPerm.isAuditor(user)) {
      throw new ActionError('حسابات (رئيس الاتحاد / المدير التنفيذي / رئيس مجلس الإدارة / عضو مجلس الإدارة) لا يغيّر حالتها إلا مراجع اللجنة', 403);
    }
    await updateRow('users', 'user_id', userId, { user_status: newStatus });
    return { targetTable: 'users', targetId: userId, message: 'تم تحديث حالة المستخدم إلى: ' + newStatus };
  },

  async approveTripAssignment({ user }, { tripId }) {
    const t = await getRow('trips', 'trip_id', tripId);
    if (!t || t.federation_number !== user.federation_id) throw new ActionError('الرحلة غير موجودة', 404);
    if (!SPerm.isTopApprover(user)) throw new ActionError('لا تملك صلاحية الاعتماد', 403);
    if (t.trip_status !== 'طلب') throw new ActionError('الرحلة ليست بانتظار الاعتماد', 400);
    const participants = await getRows('delegations', { trip_id: tripId });
    const ownRecord = participants.find(p => p.user_id === user.user_id);
    if (ownRecord && ownRecord.delegations_status === 'غير معتمد') {
      const other = SPerm.isPresident(user) ? 'المدير التنفيذي' : 'رئيس الاتحاد';
      throw new ActionError(`أنت موجود ضمن المشتركين بالانتداب ولم تتم الموافقة عليك بعد، يرجى التواصل مع ${other} للاعتماد`, 403);
    }
    await updateRow('trips', 'trip_id', tripId, { trip_status: 'قيد الصرف', request_approved_by: user.user_id, request_approval_date: nowISO() });
    // اعتماد قرار التكليف ينقل كل مشارك ممكن اعتماده (بلا تعارض مصالح) إلى
    // "قيد الصرف" — بانتظار أن يُدخل المحاسب سعر تذكرته ومرفقها، وليس إلى
    // "معتمد" مباشرة؛ الاعتماد النهائي يأتي لاحقًا بعد إدخال بيانات التذكرة.
    const pending = participants.filter(p => p.delegations_status === 'غير معتمد');
    let approvedCount = 0;
    for (const p of pending) {
      const pUser = p.user_id ? await getRow('users_public', 'user_id', p.user_id) : null;
      if (canApproveParticipantRecord(user, p, pUser)) {
        await updateRow('delegations', 'delegation_id', p.delegation_id, { delegations_status: 'قيد الصرف', request_approved_by: user.user_id, request_approval_date: nowISO() });
        approvedCount++;
      }
    }
    const remaining = pending.length - approvedCount;
    return { targetTable: 'trips', targetId: tripId, message: `تم اعتماد التكليف${approvedCount ? ` وانتقال ${approvedCount} مشارك لمرحلة إدخال بيانات التذكرة` : ''}${remaining ? ` — ${remaining} مشارك بحاجة لموافقة مستقلة` : ''}` };
  },

  async rejectTrip({ user }, { tripId }) {
    const t = await getRow('trips', 'trip_id', tripId);
    if (!t || t.federation_number !== user.federation_id) throw new ActionError('الرحلة غير موجودة', 404);
    if (!SPerm.isTopApprover(user)) throw new ActionError('لا تملك صلاحية الرفض', 403);
    if (t.trip_status !== 'طلب') throw new ActionError('الرحلة ليست بانتظار الاعتماد', 400);
    const participants = await getRows('delegations', { trip_id: tripId });
    const ownRecord = participants.find(p => p.user_id === user.user_id);
    if (ownRecord && ownRecord.delegations_status === 'غير معتمد') {
      const other = SPerm.isPresident(user) ? 'المدير التنفيذي' : 'رئيس الاتحاد';
      throw new ActionError(`أنت موجود ضمن المشتركين بالانتداب ولم تتم الموافقة عليك بعد، يرجى التواصل مع ${other} للبت في الطلب`, 403);
    }
    await updateRow('trips', 'trip_id', tripId, { trip_status: 'مرفوضة' });
    return { targetTable: 'trips', targetId: tripId, message: 'تم رفض طلب الرحلة' };
  },

  /* إقفال الرحلة — بعد اعتماد قرار التكليف (الرحلة "قيد الصرف")، ولا يجوز
     إلا إذا لم يبقَ أي مشارك بانتظار إدخال بيانات تذكرته ("قيد الصرف") أو
     بانتظار الاعتماد النهائي ("غير معتمد")، وكل المصاريف الأخرى محسومة. */
  async closeTrip({ user }, { tripId, achieved }) {
    const t = await getRow('trips', 'trip_id', tripId);
    if (!t || t.federation_number !== user.federation_id) throw new ActionError('الرحلة غير موجودة', 404);
    if (!SPerm.isTopApprover(user)) throw new ActionError('لا تملك صلاحية الإقفال', 403);
    if (t.trip_status !== 'قيد الصرف') throw new ActionError('الرحلة ليست بانتظار الإقفال', 400);
    const participants = await getRows('delegations', { trip_id: tripId });
    const otherExpenses = await getRows('other_expenses', { trip_id: tripId });
    const pendingP = participants.filter(p => p.delegations_status === 'غير معتمد' || p.delegations_status === 'قيد الصرف').length;
    const pendingE = otherExpenses.filter(e => e.expense_status === 'غير معتمد').length;
    if (pendingP > 0 || pendingE > 0) throw new ActionError('لا يمكن الإقفال قبل البتّ في كل المشاركين (اعتماد/رفض وإدخال بيانات تذاكرهم) وكل المصاريف الأخرى المعلّقة', 400);
    const achievedText = (achieved || '').trim();
    if (!achievedText) throw new ActionError('الرجاء تسجيل الأهداف المحققة قبل الإقفال', 400);
    await updateRow('trips', 'trip_id', tripId, { trip_status: 'مغلقة', achieved_results: achievedText, closure_approved_by: user.user_id, closure_approval_date: nowISO() });
    return { targetTable: 'trips', targetId: tripId, message: 'تم إقفال الرحلة' };
  },

  /* المحاسب فقط، وحصرًا لمشارك بحالة "قيد الصرف" (أي بعد اعتماد قرار
     التكليف)، يدخل سعر التذكرة ومرفقها — هذا هو التعديل الوحيد المسموح به
     على سجل المشارك بعد اعتماد قرار التكليف. بعد الحفظ تعود حالة المشارك
     إلى "غير معتمد" لتحتاج اعتماد رئيس الاتحاد أو المدير التنفيذي النهائي. */
  async submitTicketInfo({ user }, { delegationId, ticketPrice, isCarTraveler, filePath }) {
    if (!SPerm.isAccountant(user)) throw new ActionError('إدخال بيانات التذكرة من صلاحية المحاسب فقط', 403);
    const p = await getRow('delegations', 'delegation_id', delegationId);
    if (!p || p.federation_number !== user.federation_id) throw new ActionError('المشارك غير موجود', 404);
    const t = await getRow('trips', 'trip_id', p.trip_id);
    if (!t) throw new ActionError('الرحلة غير موجودة', 404);
    if (t.trip_status !== 'قيد الصرف') throw new ActionError('لا يمكن إدخال بيانات التذكرة إلا بعد اعتماد قرار التكليف', 400);
    if (p.delegations_status !== 'قيد الصرف') throw new ActionError('لا يمكن إدخال بيانات التذكرة لهذا المشارك في حالته الحالية', 400);
    const price = Number(ticketPrice);
    if (!(price >= 0)) throw new ActionError('أدخل سعر تذكرة صحيح', 400);
    if (!filePath) throw new ActionError('يجب إرفاق صورة التذكرة', 400);
    const carEligible = t.entity === 'المملكة';
    const isCar = carEligible ? !!isCarTraveler : false;
    const effectiveTicketCost = isCar ? price * 0.75 : price;
    const newTotal = effectiveTicketCost + Number(p.amount_delegations || 0);
    await updateRow('delegations', 'delegation_id', delegationId, {
      ticket_price: price, is_car_traveler: isCar, file: filePath,
      ticket_submitted: true, total_amount: newTotal, delegations_status: 'غير معتمد',
    });
    return { targetTable: 'delegations', targetId: delegationId, message: 'تم حفظ بيانات التذكرة — بانتظار اعتماد رئيس الاتحاد أو المدير التنفيذي' };
  },

  /* اعتماد مشارك — يُستخدم في جولتَي الاعتماد كلتيهما: اعتماد قرار التكليف
     (قبل إدخال بيانات التذكرة) واعتماد الصرف النهائي (بعدها)، والفرق بينهما
     هو ما إذا أُدخلت بيانات التذكرة (ticket_submitted) أم لا بعد. */
  async approveParticipant({ user }, { delegationId }) {
    const p = await getRow('delegations', 'delegation_id', delegationId);
    // مدير اللجنة/المراجع يشرفان على كل الاتحادات فلا يقيَّدان باتحادهما
    if (!p || (!SPerm.isAuditor(user) && p.federation_number !== user.federation_id)) throw new ActionError('المشارك غير موجود', 404);
    const pUser = p.user_id ? await getRow('users_public', 'user_id', p.user_id) : null;
    if (!canApproveParticipantRecord(user, p, pUser)) throw new ActionError('لا تملك صلاحية الموافقة على هذا المشارك (قد يتطلب اعتماد جهة أخرى لتفادي تعارض المصالح)', 403);
    if (p.delegations_status !== 'غير معتمد') throw new ActionError('تمت معالجة هذا المشارك بالفعل', 400);
    const nextStatus = p.ticket_submitted ? 'معتمد' : 'قيد الصرف';
    await updateRow('delegations', 'delegation_id', delegationId, { delegations_status: nextStatus, request_approved_by: user.user_id, request_approval_date: nowISO() });
    return { targetTable: 'delegations', targetId: delegationId, message: nextStatus === 'معتمد' ? 'تم اعتماد الصرف النهائي للمشارك' : 'تم اعتماد المشارك — بانتظار إدخال المحاسب لبيانات التذكرة' };
  },

  async rejectParticipant({ user }, { delegationId }) {
    const p = await getRow('delegations', 'delegation_id', delegationId);
    // مدير اللجنة/المراجع يشرفان على كل الاتحادات فلا يقيَّدان باتحادهما
    if (!p || (!SPerm.isAuditor(user) && p.federation_number !== user.federation_id)) throw new ActionError('المشارك غير موجود', 404);
    const pUser = p.user_id ? await getRow('users_public', 'user_id', p.user_id) : null;
    if (!canApproveParticipantRecord(user, p, pUser)) throw new ActionError('لا تملك صلاحية الرفض', 403);
    if (p.delegations_status !== 'غير معتمد') throw new ActionError('تمت معالجة هذا المشارك بالفعل', 400);
    await updateRow('delegations', 'delegation_id', delegationId, { delegations_status: 'مرفوض' });
    return { targetTable: 'delegations', targetId: delegationId, message: 'تم رفض المشارك' };
  },

  async approveOtherExpense({ user }, { expenseId }) {
    const e = await getRow('other_expenses', 'expense_id', expenseId);
    if (!e || e.federation_number !== user.federation_id) throw new ActionError('المصروف غير موجود', 404);
    if (!canApproveOtherExpenseFor(user, e)) throw new ActionError('لا تملك صلاحية الاعتماد (قد يتطلب اعتماد جهة أخرى تجنبًا لتعارض المصالح)', 403);
    if (e.expense_status !== 'غير معتمد') throw new ActionError('تمت معالجة هذا المصروف بالفعل', 400);
    await updateRow('other_expenses', 'expense_id', expenseId, { expense_status: 'معتمد', request_approved_by: user.user_id, request_approval_date: nowISO() });
    return { targetTable: 'other_expenses', targetId: expenseId, message: 'تم اعتماد المصروف' };
  },

  async cancelOtherExpense({ user }, { expenseId }) {
    const e = await getRow('other_expenses', 'expense_id', expenseId);
    if (!e || e.federation_number !== user.federation_id) throw new ActionError('المصروف غير موجود', 404);
    if (!canApproveOtherExpenseFor(user, e)) throw new ActionError('لا تملك صلاحية الإلغاء', 403);
    await updateRow('other_expenses', 'expense_id', expenseId, { expense_status: 'ملغى' });
    return { targetTable: 'other_expenses', targetId: expenseId, message: 'تم إلغاء المصروف' };
  },

};

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

/* =========================================================================
   استعادة كلمة المرور برمز تحقق عبر البريد الإلكتروني — ثلاث مراحل:
   1) forgot/start:  يبحث عن المستخدم باسمه، ويُنشئ رمزًا عشوائيًا من 6 أرقام،
      ويرسله فعليًا إلى البريد الإلكتروني المسجَّل على حسابه (وليس لأي عنوان
      آخر). لا يُخزَّن الرمز في قاعدة البيانات — فقط بصمة (hash) منه داخل
      تذكرة موقّعة صالحة 10 دقائق يحملها العميل. الرد لا يحتوي الرمز نفسه
      إطلاقًا ولا حتى البريد كاملاً (بريد مقنَّع فقط) — إثبات الهوية الحقيقي
      هنا هو الوصول الفعلي لصندوق البريد المسجَّل، وليس معرفة اسم المستخدم.
   2) forgot/verify: يقارن بصمة الرمز المُدخل ببصمة التذكرة، ثم يُصدر تذكرة
      ثانية محدودة الغرض (password_reset) صالحة 5 دقائق.
   3) forgot/reset:  يستخدم تذكرة password_reset لتعيين كلمة مرور جديدة
      مباشرة عبر hash_password، دون الحاجة لمعرفة كلمة المرور القديمة.
   كل مرحلة مقيّدة بمعدّل محاولات لكل IP، وردود الخطأ عامة الصياغة لتفادي
   تسريب أي معلومة عن وجود اسم مستخدم معيّن من عدمه.
   ========================================================================= */
const GENERIC_FORGOT_ERROR = { data: null, error: { message: 'تعذّر التحقق من اسم المستخدم المدخل.' } };

/* -------------------------------------------------------------------------
   فحص إعدادات البريد وإرسال رسالة تجريبية — للمشرفين فقط.
   يفيد لمعرفة أي مزوّد مفعّل وأين الخلل بالضبط دون تجربة "نسيت كلمة المرور".
   GET  /api/mail-status      → حالة الإعدادات (بدون كشف المفاتيح)
   POST /api/mail-test        → يرسل رسالة تجريبية لبريد المستخدم الحالي
   ------------------------------------------------------------------------- */
const MAIL_ADMIN_TYPES = new Set(['مراجع', 'رئيس الاتحاد', 'مدير تنفيذي', 'محاسب']);
const mask = (v) => !v ? null : (String(v).slice(0, 4) + '…' + String(v).slice(-3) + ` (${String(v).length} حرفًا)`);

/* إعادة توليد كلمة مرور مؤقتة لمستخدم وإرسالها لبريده — لمن يملك صلاحية
   إدارة المستخدمين فقط، وداخل اتحاده فقط. لا تُعرض كلمة المرور للمشرف. */
app.post('/api/user-credentials/resend', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (!supabase) return res.status(500).json({ data: null, error: { message: 'الخادم غير مهيّأ بعد.' } });
  const admin = await authenticateRequest(req);
  if (!admin) return res.status(401).json({ data: null, error: { message: 'انتهت الجلسة.', code: 'AUTH_REQUIRED' } });
  if (CANNOT_MANAGE_USERS_TYPES.has(admin.user_type)) {
    return res.status(403).json({ data: null, error: { message: 'لا تملك صلاحية إدارة المستخدمين.' } });
  }
  if (!MAIL_CONFIGURED) return res.status(400).json({ data: null, error: { message: 'إعدادات البريد غير مفعّلة على الخادم.' } });
  const targetId = String((req.body || {}).userId || '');
  if (!targetId) return res.status(400).json({ data: null, error: { message: 'معرّف المستخدم مطلوب.' } });
  const ip = req.ip || (req.connection && req.connection.remoteAddress) || 'unknown';
  try {
    const { data: target, error } = await supabase.from('users_public').select('*').eq('user_id', targetId).maybeSingle();
    if (error || !target) return res.status(404).json({ data: null, error: { message: 'المستخدم غير موجود.' } });
    const isAud = admin.user_type === 'مراجع';
    if (!isAud && target.federation_id !== admin.federation_id) {
      return res.status(403).json({ data: null, error: { message: 'هذا المستخدم لا يتبع اتحادك.' } });
    }
    if (NO_LOGIN_USER_TYPES.has(target.user_type)) {
      return res.status(400).json({ data: null, error: { message: 'هذا النوع من المستخدمين (لاعب/مرافق لاعب/حكم/متعاون) لا يملك حق الدخول للنظام أصلاً — لا تُرسل له بيانات دخول.' } });
    }
    if (!target.email) return res.status(400).json({ data: null, error: { message: 'لا يوجد بريد إلكتروني مسجَّل على هذا الحساب.' } });

    const password = generatePassword(12);
    const { data: hashed, error: hashErr } = await supabase.rpc('hash_password', { p: password });
    if (hashErr) return res.status(500).json({ data: null, error: { message: 'تعذّر تجهيز كلمة المرور.' } });

    let fedName = null;
    try {
      const f = await supabase.from('federations').select('federation_name_ar').eq('federation_id', target.federation_id).maybeSingle();
      fedName = f && f.data ? f.data.federation_name_ar : null;
    } catch (e) { /* تحسين فقط */ }

    // نرسل أولاً ثم نحفظ — حتى لا تتغيّر كلمة المرور إن فشل البريد
    const r = await sendWelcomeMail({
      to: target.email, name: target.employee_name_ar || target.employee_name_en || '',
      username: target.user_name, password, federationName: fedName,
    });
    const { error: upErr } = await supabase.from('users').update({ password: hashed }).eq('user_id', targetId);
    if (upErr) return res.status(500).json({ data: null, error: { message: 'تعذّر حفظ كلمة المرور الجديدة.' } });

    await logAudit({ user: admin, action: 'resendCredentials', success: true, targetTable: 'users', targetId, message: 'إعادة توليد كلمة مرور مؤقتة وإرسالها بالبريد', ip });
    return res.json({ data: { sent: true, to: maskEmail(target.email), provider: r.provider }, error: null });
  } catch (e) {
    await logAudit({ user: admin, action: 'resendCredentials', success: false, targetTable: 'users', targetId, message: (e && e.message) || '', ip });
    return res.status(500).json({ data: null, error: { message: (e && e.mailProblems ? e.mailProblems.join(' — ') : (e && e.message) || 'تعذّر الإرسال.') } });
  }
});

app.get('/api/mail-status', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const u = await authenticateRequest(req);
  if (!u || !MAIL_ADMIN_TYPES.has(u.user_type)) return res.status(403).json({ data: null, error: { message: 'غير مصرّح.' } });
  const notes = [];
  if (SENDGRID_API_KEY && !SENDGRID_API_KEY.startsWith('SG.')) notes.push('مفتاح SendGrid لا يبدأ بـ "SG." — غالبًا منسوخ ناقصًا.');
  if (SENDGRID_API_KEY && !SENDGRID_FROM) notes.push('SENDGRID_FROM غير معرّف.');
  if (BREVO_API_KEY && !(envTrim(process.env.BREVO_FROM_EMAIL) || envTrim(process.env.SMTP_FROM))) notes.push('BREVO_FROM_EMAIL غير معرّف.');
  return res.json({
    data: {
      providers: mailProviders().map(p => ({ name: p.name, from: p.from || null, missing: p.missing || null })),
      keys: {
        RESEND_API_KEY: mask(RESEND_API_KEY), RESEND_FROM: RESEND_FROM || null,
        BREVO_API_KEY: mask(BREVO_API_KEY), BREVO_FROM_EMAIL: envTrim(process.env.BREVO_FROM_EMAIL) || null,
        SENDGRID_API_KEY: mask(SENDGRID_API_KEY), SENDGRID_FROM: SENDGRID_FROM || null,
        SMTP_HOST: SMTP_HOST || null, SMTP_FROM: SMTP_FROM || null,
      },
      notes,
    }, error: null,
  });
});

app.post('/api/mail-test', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const u = await authenticateRequest(req);
  if (!u || !MAIL_ADMIN_TYPES.has(u.user_type)) return res.status(403).json({ data: null, error: { message: 'غير مصرّح.' } });
  const to = envTrim(u.email) || envTrim((req.body || {}).to);
  if (!to) return res.status(400).json({ data: null, error: { message: 'لا يوجد بريد إلكتروني على حسابك لإرسال الرسالة التجريبية إليه.' } });
  try {
    const r = await sendMailUnified({
      to, subject: 'رسالة تجريبية من النظام',
      text: 'إعدادات البريد تعمل بنجاح.',
      html: '<div dir="rtl" style="font-family:Tahoma,Arial,sans-serif;">إعدادات البريد تعمل بنجاح ✅</div>',
    });
    return res.json({ data: { sent: true, provider: r.provider, to: maskEmail(to) }, error: null });
  } catch (e) {
    return res.status(500).json({ data: null, error: { message: (e && e.mailProblems ? e.mailProblems.join(' — ') : (e && e.message) || 'فشل غير متوقع') } });
  }
});

app.post('/api/2fa/forgot/start', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (!supabase) return res.status(500).json({ data: null, error: { message: 'الخادم غير مهيّأ بعد.' } });
  if (!MAIL_CONFIGURED) return res.status(500).json({ data: null, error: { message: 'ميزة استعادة كلمة المرور غير مفعّلة على الخادم بعد (إعدادات البريد ناقصة). تواصل مع الدعم الفني.' } });
  const ip = req.ip || (req.connection && req.connection.remoteAddress) || 'unknown';
  if (!checkForgotRateLimit(ip)) return res.status(429).json({ data: null, error: { message: 'محاولات كثيرة جدًا. الرجاء المحاولة لاحقًا.' } });
  const { username } = req.body || {};
  if (!username) return res.status(400).json(GENERIC_FORGOT_ERROR);
  try {
    const { data, error } = await supabase.from('users_public').select('*').eq('user_name', String(username).trim()).maybeSingle();
    if (error || !data) return res.status(400).json(GENERIC_FORGOT_ERROR);
    if (data.user_status !== 'مفتوح') return res.status(400).json(GENERIC_FORGOT_ERROR);
    if (NO_LOGIN_USER_TYPES.has(data.user_type)) return res.status(400).json(GENERIC_FORGOT_ERROR);
    if (!data.email) return res.status(400).json({ data: null, error: { message: 'لا يوجد بريد إلكتروني مسجَّل على هذا الحساب — تواصل مع إدارة النظام.' } });

    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0');
    const codeHash = crypto.createHash('sha256').update(code).digest('hex');
    const ticket = signPurposeToken('password_reset_code', { uid: data.user_id, codeHash }, 10 * 60 * 1000);

    await sendMailUnified({
      to: data.email,
      subject: 'رمز التحقق لإعادة تعيين كلمة المرور',
      text: `رمز التحقق الخاص بك هو: ${code}\nصالح لمدة 10 دقائق. إذا لم تطلب إعادة تعيين كلمة المرور، تجاهل هذه الرسالة.`,
      html: `<div dir="rtl" style="font-family:Tahoma,Arial,sans-serif;">
        <p>رمز التحقق الخاص بك لإعادة تعيين كلمة المرور:</p>
        <p style="font-size:28px;font-weight:bold;letter-spacing:6px;">${code}</p>
        <p style="color:#666;">صالح لمدة 10 دقائق. إذا لم تطلب إعادة تعيين كلمة المرور، تجاهل هذه الرسالة.</p>
      </div>`,
    });

    return res.json({ data: { ticket, maskedEmail: maskEmail(data.email) }, error: null });
  } catch (e) {
    console.error('تعذّر إرسال بريد استعادة كلمة المرور:', e && e.code, e && e.responseCode, e && e.message);
    let msg = 'تعذّر إرسال البريد الإلكتروني. حاول لاحقًا أو تواصل مع الدعم الفني.';
    if (e && (e.code === 'EAUTH' || e.responseCode === 535)) {
      msg = 'تعذّر إرسال البريد: بيانات تسجيل الدخول (SMTP_USER أو SMTP_PASS) غير صحيحة. تأكد من أن SMTP_PASS هي كلمة مرور التطبيق (App Password) الصحيحة وأنها لم تُلغَ.';
    } else if (e && (e.code === 'ECONNECTION' || e.code === 'ETIMEDOUT' || e.code === 'ESOCKET')) {
      msg = 'تعذّر إرسال البريد: تعذّر الاتصال بخادم البريد. تأكد من صحة SMTP_HOST وSMTP_PORT.';
    } else if (e && e.mailProblems && e.mailProblems.length) {
      // فشل كل المزوّدين — نعرض السبب والحل كما جاء من طبقة البريد
      msg = 'تعذّر إرسال البريد. ' + e.mailProblems.join(' — ');
    } else if (e && e.message && (e.message.includes('Resend') || e.message.includes('Brevo') || e.message.includes('SendGrid'))) {
      msg = 'تعذّر إرسال البريد: ' + e.message;
    }
    return res.status(500).json({ data: null, error: { message: msg } });
  }
});

app.post('/api/2fa/forgot/verify', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  const ip = req.ip || (req.connection && req.connection.remoteAddress) || 'unknown';
  if (!checkForgotRateLimit(ip)) return res.status(429).json({ data: null, error: { message: 'محاولات كثيرة جدًا. الرجاء المحاولة لاحقًا.' } });
  const { ticket, code } = req.body || {};
  const claims = verifyPurposeToken(ticket, 'password_reset_code');
  if (!claims) return res.status(400).json({ data: null, error: { message: 'انتهت صلاحية الجلسة، الرجاء البدء من جديد.' } });
  try {
    const submittedHash = crypto.createHash('sha256').update(String(code || '').trim()).digest('hex');
    const a = Buffer.from(submittedHash);
    const b = Buffer.from(claims.codeHash || '');
    const match = a.length === b.length && crypto.timingSafeEqual(a, b);
    if (!match) return res.status(400).json({ data: null, error: { message: 'الرمز غير صحيح.' } });
    const resetTicket = signPurposeToken('password_reset', { uid: claims.uid }, 5 * 60 * 1000);
    return res.json({ data: { resetTicket }, error: null });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ data: null, error: { message: 'خطأ غير متوقع في الخادم' } });
  }
});

app.post('/api/2fa/forgot/reset', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (!supabase) return res.status(500).json({ data: null, error: { message: 'الخادم غير مهيّأ بعد.' } });
  const { resetTicket, newPassword } = req.body || {};
  const claims = verifyPurposeToken(resetTicket, 'password_reset');
  if (!claims) return res.status(400).json({ data: null, error: { message: 'انتهت صلاحية الجلسة، الرجاء البدء من جديد.' } });
  if (!newPassword || String(newPassword).length < 8) return res.status(400).json({ data: null, error: { message: 'كلمة المرور يجب ألا تقل عن 8 أحرف.' } });
  try {
    const { data: hashed, error: hashErr } = await supabase.rpc('hash_password', { p: newPassword });
    if (hashErr) return res.status(500).json({ data: null, error: { message: 'تعذّر تجهيز كلمة المرور.' } });
    const { error } = await supabase.from('users').update({ password: hashed }).eq('user_id', claims.uid);
    if (error) return res.status(500).json({ data: null, error: { message: error.message } });
    await logAudit({ user: { user_id: claims.uid, employee_name_ar: null, federation_id: null }, action: 'forgotPasswordReset', success: true, targetTable: 'users', targetId: claims.uid, message: 'إعادة تعيين كلمة المرور عبر رمز التحقق المُرسَل بالبريد الإلكتروني', ip });
    return res.json({ data: { ok: true }, error: null });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ data: null, error: { message: 'خطأ غير متوقع في الخادم' } });
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
  const { op, table, payload, pkField, id, patch, returning, fn, args, scope } = req.body || {};

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
  const currentUser = await authenticateRequest(req);
  if (!currentUser) {
    return res.status(401).json({ data: null, error: { message: 'انتهت الجلسة أو غير صالحة. الرجاء تسجيل الدخول من جديد.', code: 'AUTH_REQUIRED' } });
  }
  const isAuditor = SUPERVISOR_TYPES.has(currentUser.user_type);
  const isCommitteeManager = currentUser.user_type === 'مدير اللجنة';

  try {
    let query;
    // تُملأ عند إضافة مستخدم جديد بكلمة مرور مولّدة، لإرسالها بالبريد بعد نجاح الحفظ
    let generatedPassword = null;
    let newUserInfo = null;

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
      /* -------- تقييد النطاق (فترة زمنية / قائمة معرّفات / حالات) --------
         يُرسل من الواجهة حتى لا نحمّل كل صفوف الجدول في كل مرة. كل أسماء
         الأعمدة تُتحقق مقابل حقول الجدول المعروفة، وكل التواريخ تُتحقق
         بنمط صارم — فلا مجال لحقن أي شيء في الاستعلام. */
      if (scope && typeof scope === 'object') {
        query = applyScope(query, table, scope);
      }

    } else if (op === 'insert') {
      if (!TABLE_FIELDS[table]) return res.status(400).json({ data: null, error: { message: 'جدول غير مسموح: ' + table } });
      if (NO_WRITE_TABLES.has(table)) return res.status(403).json({ data: null, error: { message: 'غير مسموح بالكتابة في هذا الجدول.' } });

      let cleanPayload = filterFields(payload, TABLE_FIELDS[table]);

      if (table === 'users') {
        if (CANNOT_MANAGE_USERS_TYPES.has(currentUser.user_type)) {
          return res.status(403).json({ data: null, error: { message: 'لا تملك صلاحية إضافة مستخدمين.' } });
        }
        // كلمة المرور لم تعد تُكتب يدويًا: إن لم تُرسل، يولّدها الخادم ويرسلها
        // لصاحب الحساب على بريده — فلا تمر أبدًا عبر متصفح من أضاف الحساب.
        if (!cleanPayload.password) {
          if (!MAIL_CONFIGURED) {
            return res.status(400).json({ data: null, error: { message: 'إعدادات البريد غير مفعّلة على الخادم، فلا يمكن إرسال كلمة المرور للمستخدم. تواصل مع الدعم الفني.' } });
          }
          if (!cleanPayload.email) {
            return res.status(400).json({ data: null, error: { message: 'البريد الإلكتروني إلزامي — إليه تُرسل بيانات الدخول.' } });
          }
          generatedPassword = generatePassword(12);
          cleanPayload.password = generatedPassword;
        }
        const { data: hashed, error: hashErr } = await supabase.rpc('hash_password', { p: cleanPayload.password });
        if (hashErr) return res.status(500).json({ data: null, error: { message: 'تعذّر تجهيز كلمة المرور.' } });
        cleanPayload.password = hashed;
        if (!isAuditor) cleanPayload.federation_id = currentUser.federation_id;
        if (COMMITTEE_TYPES.has(cleanPayload.user_type) && !isCommitteeManager) {
          return res.status(403).json({ data: null, error: { message: 'إضافة حسابات لجنة الإشراف (مدير اللجنة / مراجع) من صلاحية مدير اللجنة حصرًا.' } });
        }
        // سؤال الاتحاد القاري خاص برئيس وأعضاء مجلس الإدارة فقط
        if (cleanPayload.user_type !== 'رئيس مجلس الادارة' && cleanPayload.user_type !== 'عضو مجلس الادارة') cleanPayload.is_continental_member = false;
        newUserInfo = {
          email: cleanPayload.email,
          name: cleanPayload.employee_name_ar || cleanPayload.employee_name_en || '',
          username: cleanPayload.user_name,
          federation_id: cleanPayload.federation_id,
        };
      } else if (table === 'expense_types') {
        if (!isAuditor) return res.status(403).json({ data: null, error: { message: 'لا تملك صلاحية إضافة نوع مصروف.' } });
      } else {
        const fedField = FED_FIELD[table];
        if (fedField && !isAuditor) cleanPayload[fedField] = currentUser.federation_id;
      }

      /* ضوابط سفر مجلس الإدارة: الخادم يعيد حساب العلامة بنفسه دائمًا ولا
         يثق بما أرسله العميل — فلا يمكن تزييف "ضمن الضوابط" لتفادي اشتراط
         اعتماد مدير اللجنة. */
      if (table === 'delegations') {
        const parentTrip = cleanPayload.trip_id ? await getRow('trips', 'trip_id', cleanPayload.trip_id) : null;
        if (!parentTrip) return res.status(400).json({ data: null, error: { message: 'الرحلة المرتبطة بهذا المشارك غير موجودة.' } });
        if (!isAuditor && parentTrip.federation_number !== currentUser.federation_id) {
          return res.status(403).json({ data: null, error: { message: 'الرحلة لا تتبع اتحادك.' } });
        }
        if (!cleanPayload.role_task || !String(cleanPayload.role_task).trim()) {
          return res.status(400).json({ data: null, error: { message: 'المهمة أو الدور في الرحلة إلزامية لكل مشارك.' } });
        }
        try {
          const lim = await computeBoardLimit(cleanPayload, parentTrip);
          cleanPayload.limit_flag = lim.flag;
          cleanPayload.limit_note = lim.note;
        } catch (e) {
          console.error('تعذّر حساب ضوابط سفر مجلس الإدارة:', e && e.message);
          return res.status(500).json({ data: null, error: { message: 'تعذّر التحقق من ضوابط سفر مجلس الإدارة.' } });
        }
      }
      if (TABLE_FIELDS[table].includes('created_by')) {
        cleanPayload.created_by = currentUser.user_id;
      }

      query = supabase.from(table).insert(cleanPayload);
      if (returning) query = query.select().single();

    } else if (op === 'update') {
      if (!TABLE_FIELDS[table]) return res.status(400).json({ data: null, error: { message: 'جدول غير مسموح: ' + table } });
      if (NO_WRITE_TABLES.has(table)) return res.status(403).json({ data: null, error: { message: 'غير مسموح بالكتابة في هذا الجدول.' } });
      if (table === 'delegations') {
        // لا يوجد تعديل عام لسجل مشارك بعد إضافته — كل التغييرات المسموحة
        // (اعتماد/رفض/إدخال بيانات التذكرة) تمر حصرًا عبر /api/action.
        return res.status(403).json({ data: null, error: { message: 'لا يمكن تعديل بيانات المشارك مباشرة — استخدم إجراءات الاعتماد/الرفض أو إدخال بيانات التذكرة.' } });
      }
      if (!pkField || !id) return res.status(400).json({ data: null, error: { message: 'معرّف السجل مطلوب للتحديث.' } });

      let cleanPatch = filterFields(patch, TABLE_FIELDS[table]);
      const fedField = FED_FIELD[table];
      if (fedField) delete cleanPatch[fedField]; // لا يجوز نقل سجل لاتحاد آخر عبر التحديث

      if (table === 'users') {
        delete cleanPatch.password; // تغيير كلمة المرور يكون فقط عبر change_password
        delete cleanPatch.user_status; // تغيير الحالة يمر حصرًا عبر /api/action
        /* الأنواع القيادية (رئيس الاتحاد / المدير التنفيذي / رئيس مجلس الإدارة /
           عضو مجلس الإدارة): لا يعدّل بياناتها — ومنها المسمى الوظيفي ونوع
           المستخدم — إلا مراجع اللجنة. ولا يرفّع أحدٌ مستخدمًا عاديًا إلى أحد
           هذه الأنواع إلا هو. التحقق هنا على الخادم، فلا يفيد تجاوز الواجهة. */
        const targetUser = await getRow('users_public', 'user_id', id);
        if (!targetUser) return res.status(404).json({ data: null, error: { message: 'المستخدم غير موجود.' } });
        if (!isAuditor) {
          if (PROTECTED_USER_TYPES.has(targetUser.user_type)) {
            return res.status(403).json({ data: null, error: { message: 'بيانات (رئيس الاتحاد / المدير التنفيذي / رئيس مجلس الإدارة / عضو مجلس الإدارة) — ومنها المسمى الوظيفي — لا يعدّلها إلا مراجع اللجنة.' } });
          }
          if (cleanPatch.user_type && PROTECTED_USER_TYPES.has(cleanPatch.user_type) && cleanPatch.user_type !== targetUser.user_type) {
            return res.status(403).json({ data: null, error: { message: 'تعيين نوع المستخدم إلى (رئيس الاتحاد / مدير تنفيذي / رئيس مجلس الإدارة / عضو مجلس الإدارة) من صلاحية مراجع اللجنة فقط.' } });
          }
        }
        if (cleanPatch.user_type && COMMITTEE_TYPES.has(cleanPatch.user_type) && cleanPatch.user_type !== targetUser.user_type && !isCommitteeManager) {
          return res.status(403).json({ data: null, error: { message: 'تعيين نوع المستخدم إلى (مدير اللجنة / مراجع) من صلاحية مدير اللجنة حصرًا.' } });
        }
        // سؤال "عضو في اتحاد قاري" خاص برئيس وأعضاء مجلس الإدارة فقط
        const finalType = cleanPatch.user_type || targetUser.user_type;
        if (finalType !== 'رئيس مجلس الادارة' && finalType !== 'عضو مجلس الادارة') cleanPatch.is_continental_member = false;
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

    // إرسال بيانات الدخول للمستخدم الجديد — بعد نجاح الحفظ فقط
    if (generatedPassword && newUserInfo) {
      let fedName = null;
      try {
        const f = await supabase.from('federations').select('federation_name_ar').eq('federation_id', newUserInfo.federation_id).maybeSingle();
        fedName = f && f.data ? f.data.federation_name_ar : null;
      } catch (e) { /* اسم الاتحاد تحسين فقط، لا يمنع الإرسال */ }
      try {
        const r = await sendWelcomeMail({
          to: newUserInfo.email, name: newUserInfo.name,
          username: newUserInfo.username, password: generatedPassword, federationName: fedName,
        });
        return res.json({ data, mail: { sent: true, to: maskEmail(newUserInfo.email), provider: r.provider }, error: null });
      } catch (e) {
        // الحساب أُنشئ فعلاً لكن البريد فشل — نخبر المشرف بوضوح ليعيد الإرسال
        console.error('تعذّر إرسال بيانات الدخول للمستخدم الجديد:', e && e.message);
        return res.json({
          data,
          mail: { sent: false, to: maskEmail(newUserInfo.email), reason: (e && e.mailProblems ? e.mailProblems.join(' — ') : (e && e.message) || 'سبب غير معروف') },
          error: null,
        });
      }
    }
    res.json({ data, error: null });
  } catch (e) {
    console.error(e);
    res.status(500).json({ data: null, error: { message: e.message || 'خطأ غير متوقع في الخادم' } });
  }
});

/* -------------------------------------------------------------------
   نقطة نهاية الإجراءات الحسّاسة (اعتماد/رفض/إقفال/تغيير حالة) — كل واحد منها
   يعيد التحقق الكامل من الصلاحية على الخادم، ويُسجَّل بسجل التدقيق دائمًا.
   ------------------------------------------------------------------- */
app.post('/api/action', async (req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  if (!supabase) {
    return res.status(500).json({ data: null, error: { message: 'الخادم غير مهيّأ بعد.' } });
  }
  const ip = req.ip || (req.connection && req.connection.remoteAddress) || 'unknown';
  const { action, ...params } = req.body || {};

  const currentUser = await authenticateRequest(req);
  if (!currentUser) {
    return res.status(401).json({ data: null, error: { message: 'انتهت الجلسة أو غير صالحة. الرجاء تسجيل الدخول من جديد.', code: 'AUTH_REQUIRED' } });
  }

  const handler = ACTIONS[action];
  if (!handler) {
    await logAudit({ user: currentUser, action: String(action || 'unknown'), success: false, message: 'إجراء غير معروف', ip });
    return res.status(400).json({ data: null, error: { message: 'إجراء غير معروف: ' + action } });
  }

  try {
    const result = await handler({ user: currentUser }, params);
    await logAudit({ user: currentUser, action, success: true, targetTable: result.targetTable, targetId: result.targetId, message: result.message, ip });
    res.json({ data: result.data || null, message: result.message, error: null });
  } catch (e) {
    const status = e instanceof ActionError ? e.status : 500;
    if (!(e instanceof ActionError)) console.error(e);
    await logAudit({ user: currentUser, action, success: false, targetTable: params && (params.custodyId ? 'custodies' : undefined), message: e.message, ip });
    res.status(status).json({ data: null, error: { message: e.message || 'خطأ غير متوقع في الخادم' } });
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
