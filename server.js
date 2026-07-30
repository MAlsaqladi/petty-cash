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
const TOKEN_TTL_MS = 7 * 24 * 60 * 60 * 1000; // أسبوع — الجلسة تنتهي بعده ويُطلب تسجيل الدخول (وبالتالي رمز التحقق بخطوتين) من جديد
const PREAUTH_TTL_MS = 10 * 60 * 1000; // 10 دقائق — رمز مؤقت بين خطوة كلمة المرور وخطوة رمز التحقق

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
/* رمز جلسة كامل (بعد نجاح كلمة المرور + رمز التحقق بخطوتين) */
function signSessionToken(uid) {
  return signToken({ uid, purpose: 'session', iat: Date.now(), exp: Date.now() + TOKEN_TTL_MS });
}
/* رمز مؤقت بين خطوة كلمة المرور وخطوة إدخال رمز التحقق — لا يصلح إطلاقًا كرمز جلسة حقيقي */
function signPreAuthToken(uid) {
  return signToken({ uid, purpose: '2fa', iat: Date.now(), exp: Date.now() + PREAUTH_TTL_MS });
}

/* =========================================================================
   التحقق بخطوتين (TOTP — نفس معيار RFC 6238 المستخدم في Google/Microsoft
   Authenticator وغيرها). تحقّقنا من صحة الخوارزمية مقابل متجهات اختبار RFC
   الرسمية قبل استخدامها. لا تحتاج مكتبة خارجية.
   ========================================================================= */
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function base32Encode(buf) {
  let bits = 0, value = 0, output = '';
  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i];
    bits += 8;
    while (bits >= 5) { output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}
function base32Decode(str) {
  str = (str || '').replace(/=+$/, '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0, value = 0;
  const out = [];
  for (const c of str) {
    const idx = BASE32_ALPHABET.indexOf(c);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}
function generateTotpSecret() { return base32Encode(crypto.randomBytes(20)); } // 160-بت، القياس الشائع
function totpCodeAtCounter(keyBuf, counter, digits) {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', keyBuf).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0xf;
  const code = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  const mod = Math.pow(10, digits);
  return String(code % mod).padStart(digits, '0');
}
/* يقبل الرمز الحالي أو رمز الخطوة السابقة/التالية (نافذة ±30 ثانية) لتفادي مشاكل فرق الساعة البسيط */
function verifyTotp(secretB32, token) {
  if (!/^\d{6}$/.test(token || '')) return false;
  const key = base32Decode(secretB32);
  const now = Date.now();
  for (let w = -1; w <= 1; w++) {
    const counter = Math.floor((now + w * 30000) / 1000 / 30);
    if (totpCodeAtCounter(key, counter, 6) === token) return true;
  }
  return false;
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

/* يتحقق من رمز الجلسة في رأس الطلب ويُرجع بيانات المستخدم الحالية، أو null إن كانت غير صالحة */
async function authenticateRequest(req) {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
  const claims = verifyToken(token);
  if (!claims || claims.purpose === '2fa') return null; // رمز مؤقت بين خطوتي الدخول لا يصلح كجلسة حقيقية
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
  isAuditor: u => u && u.user_type === 'مراجع',
  isPresident: u => u && u.user_type === 'رئيس الاتحاد',
  isExec: u => u && u.user_type === 'مدير تنفيذي',
  isAccountant: u => u && u.user_type === 'محاسب',
  isEmployee: u => u && u.user_type === 'موظف',
  isHR: u => u && u.user_type === 'موارد بشرية',
  isBoardMember: u => u && u.user_type === 'عضو مجلس الادارة',
  isBasicStaff: u => SPerm.isEmployee(u) || SPerm.isHR(u),
  isTopApprover: u => SPerm.isPresident(u) || SPerm.isExec(u),
};

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
    if (!SPerm.isTopApprover(user)) throw new ActionError('لا تملك صلاحية تغيير الحالة', 403);
    if (!USER_STATUS_VALUES.has(newStatus)) throw new ActionError('حالة غير صالحة', 400);
    const target = await getRow('users_public', 'user_id', userId);
    if (!target || target.federation_id !== user.federation_id) throw new ActionError('المستخدم غير موجود', 404);
    await updateRow('users', 'user_id', userId, { user_status: newStatus });
    return { targetTable: 'users', targetId: userId, message: 'تم تحديث حالة المستخدم إلى: ' + newStatus };
  },

  async resetUserTwoFactor({ user }, { userId }) {
    if (!SPerm.isTopApprover(user)) throw new ActionError('لا تملك صلاحية إعادة ضبط التحقق بخطوتين', 403);
    const target = await getRow('users_public', 'user_id', userId);
    if (!target || target.federation_id !== user.federation_id) throw new ActionError('المستخدم غير موجود', 404);
    await updateRow('users', 'user_id', userId, { totp_secret: null, otp_enabled: false });
    return { targetTable: 'users', targetId: userId, message: 'تمت إعادة ضبط التحقق بخطوتين — سيُطلب من المستخدم إعداده من جديد عند أول دخول' };
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
    const pending = participants.filter(p => p.delegations_status === 'غير معتمد');
    let approvedCount = 0;
    for (const p of pending) {
      const pUser = p.user_id ? await getRow('users_public', 'user_id', p.user_id) : null;
      if (canApproveParticipantRecord(user, p, pUser)) {
        await updateRow('delegations', 'delegation_id', p.delegation_id, { delegations_status: 'معتمد', request_approved_by: user.user_id, request_approval_date: nowISO() });
        approvedCount++;
      }
    }
    const remaining = pending.length - approvedCount;
    return { targetTable: 'trips', targetId: tripId, message: `تم اعتماد التكليف${approvedCount ? ` واعتماد ${approvedCount} مشارك` : ''}${remaining ? ` — ${remaining} مشارك بحاجة لموافقة مستقلة` : ''}` };
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

  async closeTrip({ user }, { tripId, achieved }) {
    const t = await getRow('trips', 'trip_id', tripId);
    if (!t || t.federation_number !== user.federation_id) throw new ActionError('الرحلة غير موجودة', 404);
    if (!SPerm.isTopApprover(user)) throw new ActionError('لا تملك صلاحية الإقفال', 403);
    const participants = await getRows('delegations', { trip_id: tripId });
    const otherExpenses = await getRows('other_expenses', { trip_id: tripId });
    const pendingP = participants.filter(p => p.delegations_status === 'غير معتمد').length;
    const pendingE = otherExpenses.filter(e => e.expense_status === 'غير معتمد').length;
    if (pendingP > 0 || pendingE > 0) throw new ActionError('لا يمكن الإقفال قبل اعتماد أو رفض/حذف كل المشاركين والمصاريف الأخرى المعلّقة', 400);
    const achievedText = (achieved || '').trim();
    if (!achievedText) throw new ActionError('الرجاء تسجيل الأهداف المحققة قبل الإقفال', 400);
    await updateRow('trips', 'trip_id', tripId, { trip_status: 'مغلقة', achieved_results: achievedText, closure_approved_by: user.user_id, closure_approval_date: nowISO() });
    return { targetTable: 'trips', targetId: tripId, message: 'تم إقفال الرحلة' };
  },

  async approveParticipant({ user }, { delegationId }) {
    const p = await getRow('delegations', 'delegation_id', delegationId);
    if (!p || p.federation_number !== user.federation_id) throw new ActionError('المشارك غير موجود', 404);
    const pUser = p.user_id ? await getRow('users_public', 'user_id', p.user_id) : null;
    if (!canApproveParticipantRecord(user, p, pUser)) throw new ActionError('لا تملك صلاحية الموافقة على هذا المشارك (قد يتطلب اعتماد جهة أخرى لتفادي تعارض المصالح)', 403);
    if (p.delegations_status !== 'غير معتمد') throw new ActionError('تمت معالجة هذا المشارك بالفعل', 400);
    await updateRow('delegations', 'delegation_id', delegationId, { delegations_status: 'معتمد', request_approved_by: user.user_id, request_approval_date: nowISO() });
    return { targetTable: 'delegations', targetId: delegationId, message: 'تم اعتماد المشارك' };
  },

  async rejectParticipant({ user }, { delegationId }) {
    const p = await getRow('delegations', 'delegation_id', delegationId);
    if (!p || p.federation_number !== user.federation_id) throw new ActionError('المشارك غير موجود', 404);
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

      // كلمة المرور صحيحة — الآن خطوة التحقق بخطوتين (TOTP) إلزامية دائمًا قبل إصدار جلسة حقيقية
      const { data: raw } = await supabase.from('users').select('otp_enabled, totp_secret').eq('user_id', u.user_id).single();
      const preToken = signPreAuthToken(u.user_id);
      if (raw && raw.otp_enabled && raw.totp_secret) {
        // المستخدم فعّل التحقق بخطوتين مسبقًا — يحتاج فقط إدخال الرمز من تطبيق المصادقة
        return res.json({ data: [], otpRequired: true, otpSetup: false, preToken, error: null });
      }
      // أول مرة: نولّد مفتاحًا جديدًا ونطلب من المستخدم مسحه/إدخاله بتطبيق مصادقة قبل تفعيله فعليًا
      const secret = generateTotpSecret();
      await supabase.from('users').update({ totp_secret: secret }).eq('user_id', u.user_id);
      return res.json({
        data: [], otpRequired: true, otpSetup: true, preToken,
        setupSecret: secret, setupAccount: u.user_name, error: null,
      });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ data: null, error: { message: e.message || 'خطأ غير متوقع في الخادم' } });
    }
  }

  /* -------- الخطوة الثانية: التحقق من رمز TOTP وإصدار جلسة حقيقية -------- */
  if (op === 'rpc' && fn === 'verify2fa') {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    if (!checkLoginRateLimit(ip)) {
      return res.status(429).json({ data: null, error: { message: 'محاولات كثيرة جدًا. الرجاء المحاولة لاحقًا.' } });
    }
    const { preToken, code } = args || {};
    const claims = verifyToken(preToken);
    if (!claims || claims.purpose !== '2fa') {
      return res.status(401).json({ data: null, error: { message: 'انتهت صلاحية عملية الدخول. الرجاء إعادة إدخال بيانات الدخول من جديد.' } });
    }
    const { data: raw, error: rawErr } = await supabase.from('users').select('*').eq('user_id', claims.uid).single();
    if (rawErr || !raw) return res.status(401).json({ data: null, error: { message: 'الحساب غير موجود.' } });
    if (raw.user_status !== 'مفتوح' || NO_LOGIN_USER_TYPES.has(raw.user_type)) {
      return res.status(401).json({ data: null, error: { message: 'الحساب غير متاح حاليًا.' } });
    }
    if (!raw.totp_secret) {
      return res.status(400).json({ data: null, error: { message: 'لم يتم إعداد التحقق بخطوتين لهذا الحساب بعد. أعد تسجيل الدخول.' } });
    }
    const ok = verifyTotp(raw.totp_secret, code);
    const { password, totp_secret, ...publicUser } = raw;
    if (!ok) {
      await logAudit({ user: publicUser, action: 'verify2fa', success: false, message: 'رمز تحقق غير صحيح', ip });
      return res.status(401).json({ data: null, error: { message: 'رمز التحقق غير صحيح.' } });
    }
    if (!raw.otp_enabled) {
      await supabase.from('users').update({ otp_enabled: true }).eq('user_id', claims.uid);
    }
    await logAudit({ user: publicUser, action: 'verify2fa', success: true, ip });
    const token = signSessionToken(claims.uid);
    return res.json({ data: [publicUser], token, error: null });
  }

  /* -------- كل ما عدا تسجيل الدخول يتطلب رمز جلسة صالح -------- */
  const currentUser = await authenticateRequest(req);
  if (!currentUser) {
    return res.status(401).json({ data: null, error: { message: 'انتهت الجلسة أو غير صالحة. الرجاء تسجيل الدخول من جديد.', code: 'AUTH_REQUIRED' } });
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
  if (!claims || claims.purpose === '2fa') return res.status(401).json({ data: null, error: { message: 'الرجاء تسجيل الدخول من جديد.', code: 'AUTH_REQUIRED' } });
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
