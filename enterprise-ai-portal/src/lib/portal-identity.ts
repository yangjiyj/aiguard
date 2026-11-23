// Portal 身份服务端声明提取：从已验证 OIDC token 的 iss/sub/groups/preferred_username/email
// 抽取稳定身份。浏览器 body 的任何覆盖都被忽略——这些字段全部来自 OIDC provider 的回执。
import type { StableIdentityClaims } from './control-plane';

export const PORTAL_EMPLOYEE_ROLE = 'employee' as const;

const MAX_DEPARTMENT_LENGTH = 256;
// 拒绝 C0 控制字符与 DEL，避免被灌进 header/审计字段。
const MAX_SUBJECT_LENGTH = 512;
const MAX_TEXT_LENGTH = 255;
const MAX_GROUP_LENGTH = 2048;
const CONTROL_CHARS = new Set<number>();
for (let c = 0; c <= 0x1f; c++) CONTROL_CHARS.add(c);
CONTROL_CHARS.add(0x7f);
const MAX_GROUP_COUNT = 512;
const MAX_DEPARTMENT_COUNT = 512;

function hasUnsafeControlChar(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    if (CONTROL_CHARS.has(value.charCodeAt(i))) return true;
  }
  return false;
}

export interface PortalIdentityClaims {
  department: string | null;
  role: typeof PORTAL_EMPLOYEE_ROLE;
}

export interface MappedOidcProfile {
  id: string;
  sub: string;
  preferred_username?: string;
  email?: string;
  name?: string;
  groups: string[];
  department: string | null;
  departments: string[];
}

// Preserve a bounded subset from Auth.js' already verified OIDC profile.
export function mapVerifiedOidcProfile(
  profile: Record<string, unknown>,
): MappedOidcProfile {
  const sub = boundedString(profile.sub, MAX_SUBJECT_LENGTH);
  if (!sub) throw new TypeError('verified OIDC profile is missing sub');
  const username = boundedString(profile.preferred_username, MAX_TEXT_LENGTH);
  const email = boundedString(profile.email, MAX_TEXT_LENGTH);
  const name = boundedString(profile.name, MAX_TEXT_LENGTH);
  const departments = normalizeDepartments(profile.departments ?? profile.department);
  return {
    id: sub,
    sub,
    ...(username ? { preferred_username: username } : {}),
    ...(email ? { email } : {}),
    ...(name ? { name } : {}),
    groups: normalizeGroups(profile.groups),
    department: departments[0] ?? null,
    departments,
  };
}

function boundedString(value: unknown, maxLength: number): string {
  if (typeof value !== 'string') return '';
  const trimmed = value.trim();
  if (
    !trimmed ||
    trimmed.length > maxLength ||
    hasUnsafeControlChar(trimmed)
  ) {
    return '';
  }
  return trimmed;
}

// 旧路径：从 claims.department 取部门名，作服务端映射提示。保留以兼容尚未接控制面的调用方。
export function mapPortalIdentityClaims(
  claims: Record<string, unknown>,
): PortalIdentityClaims {
  const rawDepartment = claims.departments ?? claims.department;
  const departments = normalizeDepartments(rawDepartment);
  const department = departments[0] ?? null;

  return {
    department,
    // 上游声明只能证明企业身份，不能授予门户或平台管理权限。
    role: PORTAL_EMPLOYEE_ROLE,
  };
}

interface VerifiedOidcAccount {
  issuer?: unknown;
  providerAccountId?: unknown;
}

interface VerifiedOidcProfile {
  sub?: unknown;
  preferred_username?: unknown;
  email?: unknown;
  groups?: unknown;
  name?: unknown;
  department?: unknown;
  departments?: unknown;
}

// 任务7：从已验证 OIDC token 抽稳定身份声明（issuer/subject/username/email/departments/groups）。
// issuer 来自 NextAuth account（IdP 已验证的签发者），不信任 profile 里的 self-claimed iss；
// subject/preferred_username/email/groups 来自 profile，由 IdP 签名背书。
// 任一关键字段缺失返回 null，调用方据此拒绝登录而不是落默认值。
export function extractStableIdentityClaims(
  account: VerifiedOidcAccount | null | undefined,
  profile: VerifiedOidcProfile | null | undefined,
): StableIdentityClaims | null {
  if (!account || !profile) return null;

  const issuer = stringOrEmpty(account.issuer);
  const subject = stringOrEmpty(profile.sub) || stringOrEmpty(account.providerAccountId);
  // OIDC preferred_username 缺失时回退 sub，保证 username 非空——它仅作显示名/审计线索，
  // 不参与稳定键（稳定键是 issuer+source_type+subject，控制面侧维护）。
  const username = stringOrEmpty(profile.preferred_username) || subject;
  const email = stringOrEmpty(profile.email);
  const departments = normalizeDepartments(profile.departments ?? profile.department);

  if (!issuer || !subject || !username) return null;

  const groups = normalizeGroups(profile.groups);
  return { issuer, subject, username, email, departments, groups };
}

function stringOrEmpty(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function normalizeDepartments(value: unknown): string[] {
  const values = Array.isArray(value) ? value : [value];
  const departments: string[] = [];
  for (const entry of values) {
    if (typeof entry !== 'string') continue;
    const trimmed = entry.trim();
    if (!trimmed || departments.includes(trimmed)) continue;
    if (trimmed.length > MAX_DEPARTMENT_LENGTH || hasUnsafeControlChar(trimmed)) continue;
    if (departments.length >= MAX_DEPARTMENT_COUNT) break;
    departments.push(trimmed);
  }
  return departments;
}

function normalizeGroups(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  const groups: string[] = [];
  for (const entry of value) {
    if (typeof entry !== 'string') continue;
    const trimmed = entry.trim();
    if (!trimmed || groups.includes(trimmed)) continue;
    if (trimmed.length > MAX_GROUP_LENGTH || hasUnsafeControlChar(trimmed)) continue;
    if (groups.length >= MAX_GROUP_COUNT) break;
    groups.push(trimmed);
  }
  return groups;
}
