-- =====================================================================
-- نظام إدارة العهد النقدية للاتحادات — مخطط قاعدة البيانات (Supabase/Postgres)
-- شغّل هذا الملف كاملاً من: Supabase Dashboard → SQL Editor → New query → Run
-- =====================================================================

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------
-- الجداول
-- ---------------------------------------------------------------------

create table if not exists federations (
  federation_id       text primary key,
  federation_name_ar  text not null,
  federation_name_en  text,
  image               text,
  created_by          text,
  created_at          timestamptz default now()
);

create table if not exists users (
  user_id             text primary key,
  federation_id       text references federations(federation_id),
  user_status         text not null default 'تحت المعالجة',
  employee_name_ar    text not null,
  employee_name_en    text,
  national_id         text,
  nationality         text,
  phone               text,
  email               text,
  user_name           text unique not null,
  password            text not null,
  user_type           text not null,
  "Job_Title"         text,
  language            text default 'ar',
  created_at          timestamptz default now(),
  created_by          text
);

create table if not exists cost_centers (
  cost_center_id        text primary key,
  federation_id          text references federations(federation_id),
  parent_cost_center_id  text references cost_centers(cost_center_id),
  cost_center_name_ar    text not null,
  cost_center_name_en    text,
  created_by             text,
  created_at             timestamptz default now()
);

create table if not exists expense_types (
  account_number    text primary key,
  expense_name_ar   text not null,
  expense_name_en   text,
  created_at        timestamptz default now(),
  created_by        text
);

create table if not exists custodies (
  custody_id               text primary key,
  federation_id            text references federations(federation_id),
  custody_status           text not null default 'قيد الاعتماد',
  received_by_user_id      text references users(user_id),
  custody_type             text,
  description_ar           text,
  description_en           text,
  disbursement_location    text,
  cost_center_id           text,               -- قائمة معرّفات مراكز تكلفة مفصولة بفاصلة
  "Opening_balance"        numeric default 0,
  "Custody_balance"        numeric default 0,
  "Closing_date"           timestamptz,
  created_by               text,
  created_at               timestamptz default now(),
  request_approved_by      text references users(user_id),
  request_approval_date    timestamptz,
  closure_approved_by      text references users(user_id),
  closure_approval_date    timestamptz,
  "Print_Count"            int default 0
);

create table if not exists custody_budgets (
  budget_id           text primary key,
  "Record_Status"     text not null default 'قيد الاعتماد',
  federation_id       text references federations(federation_id),
  custody_id          text references custodies(custody_id) on delete cascade,
  expense_type_id     text references expense_types(account_number),
  cost_center_id      text references cost_centers(cost_center_id),
  estimated_amount    numeric not null default 0,
  created_by          text,
  created_at          timestamptz default now(),
  approved_by         text references users(user_id),
  approved_at         timestamptz
);

create table if not exists custody_transfers (
  transfer_id       text primary key,
  federation_id     text references federations(federation_id),
  transfer_status   text default 'مكتمل',
  user_id           text references users(user_id),
  custody_id        text references custodies(custody_id) on delete cascade,
  statement         text,
  currency          text default 'SAR',
  foreign_amount    numeric,
  exchange_rate     numeric default 1,
  amount            numeric not null,
  file              text,
  created_at        timestamptz default now(),
  created_by        text,
  approved_by       text references users(user_id),
  approved_at       timestamptz
);

create table if not exists custody_closures (
  closure_id             text primary key,
  federation_id          text references federations(federation_id),
  disbursement_status    text not null default 'غير معتمد',
  user_id                text references users(user_id),
  custody_id             text references custodies(custody_id) on delete cascade,
  expense_type_id        text references expense_types(account_number),
  cost_center_id         text references cost_centers(cost_center_id),
  statement              text,
  currency               text default 'SAR',
  foreign_amount         numeric,
  exchange_rate          numeric default 1,
  amount                 numeric not null,
  file                   text,
  entry_location         text,
  created_by             text,
  created_at             timestamptz default now(),
  approved_by            text references users(user_id),
  approved_at            timestamptz
);

create index if not exists idx_users_fed on users(federation_id);
create index if not exists idx_custodies_fed on custodies(federation_id);
create index if not exists idx_budgets_custody on custody_budgets(custody_id);
create index if not exists idx_transfers_custody on custody_transfers(custody_id);
create index if not exists idx_closures_custody on custody_closures(custody_id);
create index if not exists idx_cc_fed on cost_centers(federation_id);
create index if not exists idx_cc_parent on cost_centers(parent_cost_center_id);

-- ---------------------------------------------------------------------
-- حماية كلمة المرور: عرض عام بدون عمود password + دوال آمنة للدخول وتغيير كلمة المرور
-- ---------------------------------------------------------------------

create or replace view users_public as
  select user_id, federation_id, user_status, employee_name_ar, employee_name_en,
         national_id, nationality, phone, email, user_name, user_type,
         "Job_Title", language, created_at, created_by
  from users;

-- دالة تسجيل الدخول: تتحقق من اسم المستخدم وكلمة المرور وتُرجع بيانات المستخدم بدون كلمة المرور
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
    where u.user_name = p_username and u.password = p_password;
end;
$$;

-- دالة تغيير كلمة المرور: تتحقق من القديمة قبل التحديث، ولا تكشف كلمة المرور الحالية أبدًا
create or replace function change_password(p_user_id text, p_old_password text, p_new_password text)
returns boolean
language plpgsql security definer
set search_path = public
as $$
declare
  v_match boolean;
begin
  select (password = p_old_password) into v_match from users where user_id = p_user_id;
  if v_match is not true then
    return false;
  end if;
  update users set password = p_new_password where user_id = p_user_id;
  return true;
end;
$$;

-- ---------------------------------------------------------------------
-- تفعيل RLS (Row Level Security)
-- ---------------------------------------------------------------------
alter table federations enable row level security;
alter table users enable row level security;
alter table cost_centers enable row level security;
alter table expense_types enable row level security;
alter table custodies enable row level security;
alter table custody_budgets enable row level security;
alter table custody_transfers enable row level security;
alter table custody_closures enable row level security;

-- ⚠️ ملاحظة أمنية:
-- في هذا الإصدار، لا يتصل المتصفح بـ Supabase مباشرة إطلاقًا. كل الطلبات
-- تمر عبر خادم Node.js (server.js) المستضاف على Render، والذي يتصل بـ
-- Supabase باستخدام مفتاح "service_role" السرّي (محفوظ في متغيرات بيئة
-- Render فقط، لا يظهر أبدًا في كود المتصفح). لذلك لا نمنح دور anon أي
-- صلاحية وصول مباشر — الوصول الوحيد المسموح هو عبر service_role الذي
-- يتجاوز RLS تلقائيًا بحكم طبيعته في Supabase، دون الحاجة لأي سياسات
-- إضافية له. هذا يعني أن قاعدة بياناتك محمية بالكامل من أي وصول مباشر
-- من الإنترنت حتى لو تسرّب رابط المشروع.

-- لا سياسات anon هنا عن قصد — RLS مفعّلة بدون سياسات = رفض كل الوصول
-- لأي دور غير service_role (وservice_role يتجاوز RLS دائمًا).

grant select on users_public to service_role;
grant execute on function login(text, text) to service_role;
grant execute on function change_password(text, text, text) to service_role;

-- =====================================================================
-- بيانات أولية اختيارية — عدّل الأسماء ثم شغّل الجزء التالي لإضافة أول اتحاد
-- (يمكنك أيضًا تركه وسيقوم التطبيق نفسه بإرشادك لإنشاء أول حساب دخول تلقائيًا)
-- =====================================================================
-- insert into federations (federation_id, federation_name_ar, federation_name_en, created_by)
-- values ('fed_001', 'الاتحاد السعودي لكرة القدم', 'Saudi Football Federation', 'system');
