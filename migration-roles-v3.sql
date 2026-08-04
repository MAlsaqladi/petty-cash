-- =====================================================================
-- ترقية: صلاحيات جديدة (رئيس مجلس الادارة / مرافق لاعب) + سؤال الاتحاد
--        القاري لرئيس مجلس الإدارة + المهمة/الدور الإلزامي لكل مشارك
--        في الرحلة.
--
-- شغّلها مرة واحدة على قاعدة بياناتك الحالية:
-- Supabase Dashboard → SQL Editor → New query → الصق هذا الملف كاملاً → Run
-- آمنة لإعادة التشغيل أكثر من مرة (idempotent) ولا تحذف أي بيانات.
-- =====================================================================

-- 1) علم: هل رئيس مجلس الإدارة عضو في اتحاد قاري؟ (يظهر الزر في الواجهة
--    عند الإضافة والتعديل لنوع "رئيس مجلس الادارة" فقط)
alter table users add column if not exists is_continental_member boolean not null default false;

-- 2) المهمة أو الدور لكل مشارك في الرحلة — حقل إلزامي من الواجهة
alter table delegations add column if not exists role_task text;

-- 3) تحديث العرض الآمن ودالة الدخول لتشمل العمود الجديد.
--    نحذف الدوال المعتمدة على العرض أولاً ثم نعيد إنشاءها بنفس المنطق.
drop function if exists login(text, text);

create or replace view users_public as
  select user_id, federation_id, user_status, employee_name_ar, employee_name_en,
         national_id, nationality, phone, email, user_name, user_type,
         "Job_Title", language, created_at, created_by, is_continental_member
  from users;

create or replace function login(p_username text, p_password text)
returns setof users_public
language plpgsql security definer
set search_path = public, extensions
as $$
begin
  return query
    select u.user_id, u.federation_id, u.user_status, u.employee_name_ar, u.employee_name_en,
           u.national_id, u.nationality, u.phone, u.email, u.user_name, u.user_type,
           u."Job_Title", u.language, u.created_at, u.created_by, u.is_continental_member
    from users u
    where u.user_name = p_username and u.password = crypt(p_password, u.password);
end;
$$;

grant select on users_public to service_role;

-- ملاحظة: عمود user_type نص حر (text) بلا قيد enum، لذلك النوعان الجديدان
-- "رئيس مجلس الادارة" و"مرافق لاعب" يعملان مباشرة بلا أي تعديل إضافي على
-- بنية الجدول. مرافق اللاعب — مثل اللاعب — لا يملك حق الدخول للنظام إطلاقًا
-- (يُرفض على مستوى الخادم وليس الواجهة فقط).
