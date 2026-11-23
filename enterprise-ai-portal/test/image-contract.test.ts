import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, '..');

function read(rel: string): string {
  return readFileSync(resolve(root, rel), 'utf8');
}

const IMAGE_NAME = process.env.PORTAL_IMAGE_NAME ?? 'enterprise-ai-portal:0.2.0-slim';
const SIZE_LIMIT_MI = 500;
const BYTES_PER_MI = 1024 * 1024;

test('镜像契约: next.config.ts 启用 standalone', () => {
  const cfg = read('next.config.ts');
  assert.match(
    cfg,
    /output:\s*['"]standalone['"]/,
    'next.config.ts 必须设置 output: "standalone"',
  );
});

test('镜像契约: Dockerfile runtime 阶段不执行 npm ci', () => {
  const dockerfile = read('Dockerfile');
  const lines = dockerfile.split('\n');
  const stageLines: string[] = [];
  let currentStage = '';
  for (const line of lines) {
    const fromMatch = line.match(/^\s*FROM\s+\S+\s+(?:AS|as)\s+(\S+)/);
    if (fromMatch) {
      currentStage = fromMatch[1];
      stageLines.push(`--- STAGE: ${currentStage} ---`);
    }
    stageLines.push(`[${currentStage}] ${line}`);
  }
  const runtimeIdx = stageLines.findIndex((l) =>
    l.startsWith('--- STAGE: runtime') || l.startsWith('--- STAGE: final'),
  );
  assert.ok(runtimeIdx >= 0, '必须存在 runtime 或 final 阶段');
  const runtimeBlock = stageLines.slice(runtimeIdx).join('\n');
  assert.doesNotMatch(
    runtimeBlock,
    /npm\s+ci/,
    'runtime/final 阶段不得执行 npm ci（避免全量依赖进入生产镜像）',
  );
  assert.doesNotMatch(
    runtimeBlock,
    /npm\s+install/,
    'runtime/final 阶段不得执行 npm install',
  );
});

test('镜像契约: prisma-cli 复用锁定依赖且不重新安装', () => {
  const dockerfile = read('Dockerfile');
  assert.match(
    dockerfile,
    /^FROM\s+deps\s+AS\s+prisma-cli\s*$/m,
    'prisma-cli 必须从 deps 阶段复用 package-lock 锁定的依赖',
  );

  const prismaCliStart = dockerfile.indexOf('FROM deps AS prisma-cli');
  assert.ok(prismaCliStart >= 0, '必须存在 prisma-cli 阶段');
  const remainingStages = dockerfile.slice(prismaCliStart + 'FROM deps AS prisma-cli'.length);
  const nextStage = remainingStages.search(/^FROM\s/m);
  const prismaCli = nextStage >= 0 ? remainingStages.slice(0, nextStage) : remainingStages;
  assert.doesNotMatch(
    prismaCli,
    /npm\s+(?:init|install|ci)\b/,
    'prisma-cli 不得绕过已锁定依赖重新安装，离线构建不能访问 npm registry',
  );
});

test('镜像契约: Dockerfile runtime 使用非 root 用户', () => {
  const dockerfile = read('Dockerfile');
  assert.match(dockerfile, /USER\s+\S+/, 'runtime 必须指定非 root 用户');
  assert.doesNotMatch(dockerfile, /USER\s+root\b/, '不得以 root 运行');
  assert.doesNotMatch(
    dockerfile,
    /RUN\s+chown\s+-R\s+portal:portal\s+\/app/,
    'runtime 不得递归 chown /app 产生重复镜像层',
  );
});

test('镜像契约: 启动脚本先执行数据库初始化，失败时退出非零', () => {
  const entry = existsSync(resolve(root, 'docker-entrypoint.sh'))
    ? read('docker-entrypoint.sh')
    : read('Dockerfile');
  assert.match(
    entry,
    /db\s+push/,
    '启动流程必须先执行 prisma db push',
  );
  assert.match(
    entry,
    /set\s+-e/,
    '必须 set -e 保证数据库初始化失败时阻止 Web 服务启动',
  );
  assert.match(entry, /node_modules\/\.bin\/prisma\s+db\s+push/, '必须使用 Prisma 公共 CLI 入口');
  assert.doesNotMatch(
    entry,
    /node_modules\/prisma\/build\/index\.js/,
    '不得依赖 Prisma 私有实现路径',
  );
  assert.match(
    entry,
    /HOSTNAME="\$\{PORTAL_BIND_HOST:-0\.0\.0\.0\}"/,
    '必须覆盖 Docker 自动注入的 HOSTNAME，保证 localhost 健康检查可达',
  );
});

test('镜像契约: runtime 复制 standalone 产物', () => {
  const dockerfile = read('Dockerfile');
  assert.match(
    dockerfile,
    /standalone/,
    'runtime 必须复制 standalone 产物',
  );
  assert.doesNotMatch(
    dockerfile,
    /next\s+start/,
    'runtime 不得使用 next start（应使用 standalone server.js）',
  );
});

test('镜像契约: 生产镜像大小不超过 500 MiB', { todo: !process.env.CHECK_IMAGE_SIZE ? '需设置 CHECK_IMAGE_SIZE=1 并先构建镜像' : undefined }, () => {
  if (!process.env.CHECK_IMAGE_SIZE) return;
  let sizeBytes: number;
  try {
    const out = execFileSync('docker', ['image', 'inspect', IMAGE_NAME, '--format', '{{.Size}}'], {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    }).trim();
    sizeBytes = parseInt(out, 10);
  } catch {
    assert.fail(`无法检查镜像 ${IMAGE_NAME}，请先构建`);
    return;
  }
  const sizeMi = sizeBytes / BYTES_PER_MI;
  assert.ok(
    sizeBytes <= SIZE_LIMIT_MI * BYTES_PER_MI,
    `镜像 ${sizeMi.toFixed(1)} MiB 超过 ${SIZE_LIMIT_MI} MiB 限制`,
  );
});
