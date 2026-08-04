-- =====================================================================
-- ترقية v4: صلاحية "مدير اللجنة" + سؤال الاتحاد القاري لأعضاء مجلس الإدارة
--           + ضوابط سفر رئيس وأعضاء مجلس الإدارة (علامة التجاوز والملاحظة)
--
-- شغّلها مرة واحدة على قاعدة بياناتك الحالية:
-- Supabase Dashboard → SQL Editor → New query → الصق هذا الملف كاملاً → Run
-- آمنة لإعادة التشغيل أكثر من مرة (idempotent) ولا تحذف أي بيانات.
-- ⚠️ إن لم تكن شغّلت migration-roles-v3.sql بعد، شغّله أولاً ثم هذا الملف.
-- =====================================================================

-- علامة ضوابط سفر مجلس الإدارة على كل مشارك:
--   'تجاوز'   → أحمر: تجاوز الضوابط، ولا يعتمد سفره إلا مدير اللجنة
--   'عند الحد' → أصفر: بلغ حدّه المسموح ووقف عنده
--   NULL      → ضمن الضوابط
alter table delegations add column if not exists limit_flag text;
-- نص الملاحظة الموضّحة لسبب العلامة (يُحسب على الخادم عند الإضافة)
alter table delegations add column if not exists limit_note text;

create index if not exists idx_delegations_limit_flag on delegations(limit_flag);
-- يسرّع حساب الاستهلاك السنوي لكل مشارك
create index if not exists idx_delegations_user_start on delegations(user_id, start_date);

-- ملاحظة: عمود user_type نص حر (text) بلا قيد enum، فالنوع الجديد
-- "مدير اللجنة" يعمل مباشرة بلا تعديل على بنية الجدول. وعمود
-- is_continental_member (المضاف في v3) صار يُستخدم الآن لرئيس مجلس الإدارة
-- ولأعضائه معًا.

-- (اختياري) إنشاء حساب مدير اللجنة الأول — عدّل القيم قبل التشغيل:
-- insert into users (user_id, federation_id, user_status, employee_name_ar, user_name, password, user_type)
-- values ('u_cm_001', 'fed_001', 'مفتوح', 'اسم مدير اللجنة', 'committee',
--         crypt('اختر-كلمة-مرور-قوية', gen_salt('bf')), 'مدير اللجنة');
