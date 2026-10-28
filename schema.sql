-- ARGUS 生产库表结构（PostgreSQL 15+）
-- 内存实现（internal/store）用于开发与演示；生产实现只需实现同一组接口。
-- 设计要点：
--   1) 范围是结构化事实（task_scope），不是提示词；
--   2) 意图指纹有唯一索引，去重由数据库保证，不靠模型自比对；
--   3) 预算是独立账本（budget_ledger），扣减用原子 UPDATE；
--   4) 证据正文不入库，库里只放索引与哈希（正文在 WORM 存储）；
--   5) scope_violation 是三层闸门的统一记账，任何一次越界都必须留痕。

BEGIN;

CREATE TABLE IF NOT EXISTS tenant (
  id          BIGSERIAL PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS task (
  id          BIGSERIAL PRIMARY KEY,
  tenant_id   BIGINT NOT NULL REFERENCES tenant(id),
  name        TEXT NOT NULL,
  goal        TEXT NOT NULL,
  state       TEXT NOT NULL DEFAULT 'pending'
              CHECK (state IN ('pending','running','done','stopped')),
  workers     INT  NOT NULL DEFAULT 3 CHECK (workers BETWEEN 1 AND 32),
  deadline    TIMESTAMPTZ,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 授权范围：一条规则一行。默认拒绝语义由应用层实现（空表 = 拒绝一切）。
CREATE TABLE IF NOT EXISTS task_scope (
  task_id  BIGINT NOT NULL REFERENCES task(id) ON DELETE CASCADE,
  kind     TEXT NOT NULL CHECK (kind IN ('exact_domain','domain_suffix','cidr','exact_ip','exact_url')),
  value    TEXT NOT NULL,
  PRIMARY KEY (task_id, kind, value)
);

CREATE TABLE IF NOT EXISTS asset (
  id            BIGSERIAL PRIMARY KEY,
  tenant_id     BIGINT NOT NULL REFERENCES tenant(id),
  first_task_id BIGINT REFERENCES task(id),
  kind          TEXT NOT NULL CHECK (kind IN ('root_domain','ip','subdomain','app','service','endpoint')),
  key           TEXT NOT NULL,          -- 归一化后的唯一键（域名/IP/URL）
  attrs         JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, kind, key)
);

CREATE TABLE IF NOT EXISTS exploration_node (
  id         BIGSERIAL PRIMARY KEY,
  task_id    BIGINT NOT NULL REFERENCES task(id) ON DELETE CASCADE,
  kind       TEXT NOT NULL CHECK (kind IN ('goal','intent','fact','finding','hint','digest')),
  state      TEXT NOT NULL DEFAULT 'open',
  summary    TEXT NOT NULL,
  action     TEXT,
  target     TEXT,
  asset_id   BIGINT REFERENCES asset(id),
  fp         CHAR(64),
  owner      TEXT,
  priority   INT NOT NULL DEFAULT 0,
  attempts   INT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 意图去重：DB 级唯一约束（这是 ARTEX 缺失的那一层）
CREATE UNIQUE INDEX IF NOT EXISTS exploration_intent_fp_uniq
  ON exploration_node (task_id, fp) WHERE kind = 'intent' AND fp IS NOT NULL;

-- 领养意图：CAS 语义，RowsAffected==1 才代表领到
-- UPDATE exploration_node SET state='running', owner=$1, updated_at=now()
--  WHERE id=$2 AND task_id=$3 AND state='open';

CREATE INDEX IF NOT EXISTS exploration_frontier_idx
  ON exploration_node (task_id, state, priority DESC, id) WHERE kind = 'intent';

CREATE TABLE IF NOT EXISTS finding (
  id          BIGSERIAL PRIMARY KEY,
  task_id     BIGINT NOT NULL REFERENCES task(id) ON DELETE CASCADE,
  node_id     BIGINT REFERENCES exploration_node(id),
  vuln_class  TEXT NOT NULL,
  severity    TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
  title       TEXT NOT NULL,
  target      TEXT NOT NULL,
  evidence_id TEXT NOT NULL,            -- 非空约束：没有证据不算结论
  attack_id   TEXT,
  attack_tactic TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS finding_task_idx ON finding (task_id, created_at DESC);

-- 证据索引（正文在 WORM 存储；这里只放哈希链与定位）
CREATE TABLE IF NOT EXISTS evidence_index (
  id          TEXT PRIMARY KEY,          -- ev-000001
  seq         BIGINT NOT NULL UNIQUE,
  task_id     BIGINT NOT NULL REFERENCES task(id) ON DELETE CASCADE,
  node_id     BIGINT,
  kind        TEXT NOT NULL,
  uri         TEXT NOT NULL,             -- s3://bucket/key
  prev_hash   CHAR(64) NOT NULL,
  hash        CHAR(64) NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 三层预算账本：原子扣减
CREATE TABLE IF NOT EXISTS budget_ledger (
  scope   TEXT NOT NULL,                 -- 'intent:123' | 'task:45' | 'day:2026-10-27'
  kind    TEXT NOT NULL CHECK (kind IN ('tokens','cost','steps','seconds')),
  used    BIGINT NOT NULL DEFAULT 0 CHECK (used >= 0),
  cap     BIGINT NOT NULL CHECK (cap > 0),
  PRIMARY KEY (scope, kind)
);

-- 原子扣减（超限则影响 0 行）：
-- UPDATE budget_ledger SET used = used + $3
--  WHERE scope=$1 AND kind=$2 AND used + $3 <= cap;

-- 越界记账：三个层各自的记录，用于看板与复盘
CREATE TABLE IF NOT EXISTS scope_violation (
  id         BIGSERIAL PRIMARY KEY,
  task_id    BIGINT NOT NULL REFERENCES task(id) ON DELETE CASCADE,
  node_id    BIGINT,
  layer      TEXT NOT NULL CHECK (layer IN ('intent','exec','network')),
  tool       TEXT,
  target     TEXT NOT NULL,
  reason     TEXT NOT NULL,
  raw        TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS scope_violation_task_idx ON scope_violation (task_id, layer, created_at DESC);

-- 审计：所有状态迁移与人工操作
CREATE TABLE IF NOT EXISTS audit_log (
  id         BIGSERIAL PRIMARY KEY,
  actor      TEXT NOT NULL,
  action     TEXT NOT NULL,
  task_id    BIGINT,
  detail     JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

COMMIT;

-- 迁移原则：只追加（ALTER TABLE ADD COLUMN / CREATE INDEX CONCURRENTLY），
-- 不做破坏性变更；每次启动幂等执行（与 ARTEX 的启动即迁移思路一致）。
