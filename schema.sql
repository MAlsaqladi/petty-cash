-- =====================================================================
-- نظام إدارة العهد النقدية للاتحادات — مخطط قاعدة البيانات (Supabase/Postgres)
-- شغّل هذا الملف كاملاً من: Supabase Dashboard → SQL Editor → New query → Run
-- =====================================================================

create extension if not exists pgcrypto;

-- نضبط مسار البحث لهذه الجلسة حتى تُوجَد دوال pgcrypto (crypt/gen_salt) بغض
-- النظر عن الـ schema اللي ركّبت فيه Supabase الامتداد (عادة "extensions")
set search_path = public, extensions;

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
  totp_secret         text,
  otp_enabled         boolean not null default false,
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

-- دالة مساعدة يستخدمها الخادم (server.js) لتشفير كلمة مرور جديدة عند إنشاء مستخدم
create or replace function hash_password(p text)
returns text
language sql
security definer
set search_path = public, extensions
as $$ select crypt(p, gen_salt('bf')); $$;

-- دالة تسجيل الدخول: تتحقق من اسم المستخدم وكلمة المرور (مقارنة تجزئة bcrypt) وتُرجع بيانات المستخدم بدون كلمة المرور
create or replace function login(p_username text, p_password text)
returns setof users_public
language plpgsql security definer
set search_path = public, extensions
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

-- دالة تغيير كلمة المرور: تتحقق من القديمة (تجزئة) قبل التحديث، وتخزّن الجديدة مشفّرة دائمًا
create or replace function change_password(p_user_id text, p_old_password text, p_new_password text)
returns boolean
language plpgsql security definer
set search_path = public, extensions
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
grant execute on function hash_password(text) to service_role;

-- ---------------------------------------------------------------------
-- تخزين المرفقات (صور/ملفات PDF للتحويلات والمصاريف)
-- ---------------------------------------------------------------------
-- bucket خاص (غير عام) — الوصول إليه فقط عبر الخادم (service_role) الذي
-- يولّد روابط مؤقتة صالحة لعدة دقائق عند الحاجة لعرض المرفق.
insert into storage.buckets (id, name, public)
values ('attachments', 'attachments', false)
on conflict (id) do nothing;
-- لا حاجة لأي سياسات إضافية على storage.objects لأن service_role يتجاوز RLS دائمًا.

-- =====================================================================
-- نظام إدارة الانتدابات وتذاكر السفر — نفس مبدأ نظام العهد تمامًا
-- (خادم واحد، service_role واحد، RLS بلا سياسات anon = رفض كل وصول مباشر)
-- =====================================================================

create table if not exists trips (
  trip_id                       text primary key,
  federation_number             text references federations(federation_id),
  trip_status                   text not null default 'طلب',
  trip_name_ar                  text not null,
  trip_name_en                  text,
  trip_type                     text,
  justifications                text,
  desired_results                text,
  achieved_results              text,
  cost_centers_id                text,           -- قائمة معرّفات مراكز تكلفة مفصولة بفاصلة (نفس أسلوب custodies.cost_center_id)
  start_date                     date,
  end_date                       date,
  trip_days_count                int,
  entity                         text,           -- إلى أين: المملكة / أفريقيا والشرق الأوسط / آسيا / أوروبا
  other_notes                    text,
  has_sports_equipment           boolean default false,
  is_transportation_available    boolean default false,
  is_accommodation_available     boolean default false,
  file                           text,
  "Balance_trips"                numeric default 0,
  created_by                     text,
  created_at                     timestamptz default now(),
  request_approved_by            text references users(user_id),
  request_approval_date          timestamptz,
  closure_approved_by            text references users(user_id),
  closure_approval_date          timestamptz
);

create table if not exists delegations (
  delegation_id                  text primary key,
  trip_id                        text references trips(trip_id) on delete cascade,
  federation_number              text references federations(federation_id),
  delegations_status             text not null default 'غير معتمد',
  user_type                      text,
  user_id                        text references users(user_id),
  amount_delegations             numeric default 0,
  is_linked_to_trip              boolean default true,
  justification                  text,
  delegation_days_count          int,
  start_date                     date,
  end_date                       date,
  is_transportation_available    boolean default false,
  is_accommodation_available     boolean default false,
  achieved_goal                  text,
  hours_count                    numeric,
  ticket_type                    text,
  is_car_traveler                boolean default false,
  ticket_price                   numeric default 0,
  total_amount                   numeric default 0,
  file                           text,
  created_by                     text,
  created_at                     timestamptz default now(),
  request_approved_by            text references users(user_id),
  request_approval_date          timestamptz
);

create table if not exists other_expenses (
  expense_id                     text primary key,
  trip_id                        text references trips(trip_id) on delete cascade,
  federation_number              text references federations(federation_id),
  expense_status                 text not null default 'غير معتمد',
  expense_type                   text,
  beneficiary                    text,
  justification                  text,
  amount                         numeric default 0,
  file                           text,
  created_by                     text,
  created_at                     timestamptz default now(),
  request_approved_by            text references users(user_id),
  request_approval_date          timestamptz
);

create index if not exists idx_trips_fed on trips(federation_number);
create index if not exists idx_delegations_trip on delegations(trip_id);
create index if not exists idx_delegations_fed on delegations(federation_number);
create index if not exists idx_other_expenses_trip on other_expenses(trip_id);
create index if not exists idx_other_expenses_fed on other_expenses(federation_number);

alter table trips enable row level security;
alter table delegations enable row level security;
alter table other_expenses enable row level security;
-- لا سياسات anon هنا عن قصد — نفس مبدأ جداول العهد بالضبط (service_role فقط يصل).

-- =====================================================================
-- سجل التدقيق (Audit Log) — يسجّل كل محاولة إجراء حسّاس (اعتماد/رفض/إقفال/تغيير
-- صلاحية) من الخادم مباشرة، سواء نجحت أو فشلت، لمن ومتى ولماذا.
-- =====================================================================
create table if not exists audit_log (
  id                bigserial primary key,
  created_at        timestamptz not null default now(),
  user_id           text,
  user_name         text,
  federation_id     text,
  action            text not null,
  success           boolean not null,
  target_table      text,
  target_id         text,
  message           text,
  ip                text
);
create index if not exists idx_audit_log_user on audit_log(user_id);
create index if not exists idx_audit_log_fed on audit_log(federation_id);
create index if not exists idx_audit_log_created on audit_log(created_at desc);

alter table audit_log enable row level security;
-- لا سياسات anon هنا عن قصد — نفس مبدأ باقي الجداول (service_role فقط يصل، والقراءة من
-- الواجهة تمر عبر مسار مخصّص server-side وليس عبر /api/db العام).

-- =====================================================================
-- بيانات أولية اختيارية — عدّل الأسماء ثم شغّل الجزء التالي لإضافة أول اتحاد
-- (يمكنك أيضًا تركه وسيقوم التطبيق نفسه بإرشادك لإنشاء أول حساب دخول تلقائيًا)
-- =====================================================================
-- insert into federations (federation_id, federation_name_ar, federation_name_en, created_by)
-- values ('fed_001', 'الاتحاد السعودي لكرة القدم', 'Saudi Football Federation', 'system');
