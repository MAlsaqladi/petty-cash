-- =====================================================================
-- ترقية أمنية — شغّلها مرة واحدة على قاعدة بياناتك الحالية
-- Supabase Dashboard → SQL Editor → New query → الصق هذا الملف كاملاً → Run
--
-- هذا الملف آمن لإعادة التشغيل أكثر من مرة (كل أوامره idempotent) ولا يحذف
-- أي بيانات — فقط يشفّر كلمات المرور المخزّنة كنص صريح ويحدّث دالتي الدخول
-- وتغيير كلمة المرور لاستخدام التشفير.
-- =====================================================================

create extension if not exists pgcrypto;

-- دالة مساعدة يستخدمها الخادم (server.js) لتشفير كلمة مرور جديدة عند إنشاء مستخدم
create or replace function hash_password(p text)
returns text
language sql
security definer
set search_path = public
as $$ select crypt(p, gen_salt('bf')); $$;

grant execute on function hash_password(text) to service_role;

-- دالة تسجيل الدخول: تقارن كلمة المرور المُدخلة بالتجزئة المخزّنة (bcrypt)
create or replace function login(p_username text, p_password text)
returns setof users_public
language plpgsql security definer
set search_path = public
as $$
begin
  return query
    select u.user_id, u.federation_id, u.user_status, u.employee_name_ar, u.employee_name_en,
           u.national_id, u.nationality, u.phone, u.email, u.user_name, u.user_type,
           u."Job_Title", u.language, u.created_at, u.created_by
    from users u
    where u.user_name = p_username and u.password = crypt(p_password, u.password);
end;
$$;

-- دالة تغيير كلمة المرور: تتحقق من القديمة (مقارنة تجزئة) ثم تخزّن الجديدة مشفّرة
create or replace function change_password(p_user_id text, p_old_password text, p_new_password text)
returns boolean
language plpgsql security definer
set search_path = public
as $$
declare
  v_match boolean;
begin
  select (password = crypt(p_old_password, password)) into v_match from users where user_id = p_user_id;
  if v_match is not true then
    return false;
  end if;
  update users set password = crypt(p_new_password, gen_salt('bf')) where user_id = p_user_id;
  return true;
end;
$$;

grant execute on function login(text, text) to service_role;
grant execute on function change_password(text, text, text) to service_role;

-- ---------------------------------------------------------------------
-- الترحيل الفعلي: تشفير أي كلمة مرور لا تزال نصًا صريحًا (لن يعيد تشفير
-- كلمة تم تشفيرها مسبقًا — الشرط يتحقق من صيغة bcrypt القياسية $2a$/$2b$/$2y$)
-- ---------------------------------------------------------------------
update users
set password = crypt(password, gen_salt('bf'))
where password !~ '^\$2[aby]\$';

-- تحقّق سريع بعد التشغيل (اختياري) — يجب ألا تُظهر هذه الجملة أي صفوف:
-- select user_id, user_name from users where password !~ '^\$2[aby]\$';
