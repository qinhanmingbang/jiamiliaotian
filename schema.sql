-- =====================================================================
--  小圈子 · 私人聊天  数据库脚本
--  使用方法：Supabase 后台 → SQL Editor → New query → 粘贴全部内容 → Run
--  ★ 运行前，先把下面第 1 步里的邀请码改成你自己的（朋友注册时要输入）
--  脚本可以重复运行，不会重复创建。
-- =====================================================================


-- ---------------------------------------------------------------------
-- 1. 配置表：保存邀请码（没有任何访问策略，网页端读不到，只有下面的函数能读）
-- ---------------------------------------------------------------------
create table if not exists public.app_config (
  key   text primary key,
  value text not null
);
alter table public.app_config enable row level security;

-- ★★★ 把下面引号里的内容改成你自己的邀请码（越长越安全，建议 10 位以上） ★★★
insert into public.app_config (key, value)
values ('invite_code', '987654321')
on conflict (key) do nothing;

-- 以后想换邀请码，单独运行这一句即可：
-- update public.app_config set value = '新的邀请码' where key = 'invite_code';


-- ---------------------------------------------------------------------
-- 2. 用户资料表：用户名（登录用邮箱，聊天和加好友用用户名）
-- ---------------------------------------------------------------------
create table if not exists public.profiles (
  id         uuid primary key references auth.users (id) on delete cascade,
  username   text not null unique check (username ~ '^[a-z0-9_]{3,20}$'),
  created_at timestamptz not null default now()
);
alter table public.profiles enable row level security;

drop policy if exists "profiles_select" on public.profiles;
create policy "profiles_select" on public.profiles
  for select to authenticated using (true);
-- 不开放 insert / update / delete：资料只能由下面的触发器在注册时创建


-- ---------------------------------------------------------------------
-- 3. 注册检查：用户名格式 / 邀请码 / 是否被占用（网页注册前先调用）
-- ---------------------------------------------------------------------
create or replace function public.check_signup(u text, invite text)
returns text
language plpgsql
security definer
set search_path = public
as $$
begin
  if u is null or u !~ '^[a-z0-9_]{3,20}$' then
    return 'bad_username';
  end if;
  if invite is distinct from (select value from public.app_config where key = 'invite_code') then
    return 'bad_invite';
  end if;
  if exists (select 1 from public.profiles where username = u) then
    return 'username_taken';
  end if;
  return 'ok';
end;
$$;

revoke all on function public.check_signup(text, text) from public;
grant execute on function public.check_signup(text, text) to anon, authenticated;


-- ---------------------------------------------------------------------
-- 4. 注册触发器：新用户注册时再检查一遍（防止有人绕过网页直接调接口），并创建资料
-- ---------------------------------------------------------------------
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  u   text := lower(coalesce(new.raw_user_meta_data ->> 'username', ''));
  inv text := coalesce(new.raw_user_meta_data ->> 'invite', '');
begin
  if public.check_signup(u, inv) <> 'ok' then
    raise exception 'signup_rejected';
  end if;
  insert into public.profiles (id, username) values (new.id, u);
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();


-- ---------------------------------------------------------------------
-- 5. 好友关系表
--    requester 发起申请，addressee 接受后 status 变为 accepted
-- ---------------------------------------------------------------------
create table if not exists public.friendships (
  id         bigint generated always as identity primary key,
  requester  uuid not null references public.profiles (id) on delete cascade,
  addressee  uuid not null references public.profiles (id) on delete cascade,
  status     text not null default 'pending' check (status in ('pending', 'accepted')),
  created_at timestamptz not null default now(),
  check (requester <> addressee)
);

-- 同一对人只能有一条关系（A 加 B 和 B 加 A 算同一条）
create unique index if not exists friendships_pair_idx
  on public.friendships (least(requester, addressee), greatest(requester, addressee));

alter table public.friendships enable row level security;

drop policy if exists "fs_select" on public.friendships;
create policy "fs_select" on public.friendships
  for select to authenticated
  using (auth.uid() in (requester, addressee));

drop policy if exists "fs_insert" on public.friendships;
create policy "fs_insert" on public.friendships
  for insert to authenticated
  with check (requester = auth.uid() and status = 'pending');

-- 只有被申请的一方可以把 pending 改成 accepted
drop policy if exists "fs_update" on public.friendships;
create policy "fs_update" on public.friendships
  for update to authenticated
  using (addressee = auth.uid() and status = 'pending')
  with check (addressee = auth.uid() and status = 'accepted');

-- 双方都可以删除（拒绝申请 / 撤销申请 / 删除好友）
drop policy if exists "fs_delete" on public.friendships;
create policy "fs_delete" on public.friendships
  for delete to authenticated
  using (auth.uid() in (requester, addressee));

-- 只允许修改 status 这一列，其他列（谁加谁）不能改
revoke update on public.friendships from authenticated, anon;
grant update (status) on public.friendships to authenticated;


-- ---------------------------------------------------------------------
-- 6. 判断是否好友的函数（给消息表的发送权限用）
-- ---------------------------------------------------------------------
create or replace function public.are_friends(a uuid, b uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select auth.uid() in (a, b)
     and exists (
       select 1 from public.friendships f
       where f.status = 'accepted'
         and ((f.requester = a and f.addressee = b)
           or (f.requester = b and f.addressee = a))
     );
$$;

revoke all on function public.are_friends(uuid, uuid) from public;
grant execute on function public.are_friends(uuid, uuid) to authenticated;


-- ---------------------------------------------------------------------
-- 7. 消息表
-- ---------------------------------------------------------------------
create table if not exists public.messages (
  id         bigint generated always as identity primary key,
  sender     uuid not null references public.profiles (id) on delete cascade,
  receiver   uuid not null references public.profiles (id) on delete cascade,
  content    text not null check (char_length(content) between 1 and 2000),
  created_at timestamptz not null default now(),
  check (sender <> receiver)
);

create index if not exists messages_sender_idx   on public.messages (sender, id);
create index if not exists messages_receiver_idx on public.messages (receiver, id);

alter table public.messages enable row level security;

-- 只能看到自己发出的或发给自己的消息
drop policy if exists "msg_select" on public.messages;
create policy "msg_select" on public.messages
  for select to authenticated
  using (auth.uid() in (sender, receiver));

-- 只能以自己的名义发，而且对方必须已经是好友
drop policy if exists "msg_insert" on public.messages;
create policy "msg_insert" on public.messages
  for insert to authenticated
  with check (sender = auth.uid() and public.are_friends(sender, receiver));

-- 不开放修改和删除
revoke update, delete on public.messages from authenticated, anon;


-- ---------------------------------------------------------------------
-- 8. 开启实时推送（新消息、好友申请即时出现）
-- ---------------------------------------------------------------------
do $$
begin
  begin
    alter publication supabase_realtime add table public.messages;
  exception when duplicate_object then null;
  end;
  begin
    alter publication supabase_realtime add table public.friendships;
  exception when duplicate_object then null;
  end;
end $$;


-- =====================================================================
--  完成。到 Table Editor 应该能看到：app_config、profiles、friendships、messages
-- =====================================================================
