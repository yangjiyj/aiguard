// 全托管建分组（S4）：一次请求把「网关 project + 模型策略 + 本地映射规则」三件套建齐。
// 顺序刻意为 project → model_policy → rule：
//   映射规则（真正激活分组、决定员工落哪个 project 的东西）永远最后建，
//   因此任一网关步骤失败都不会遗留悬空规则——这就是「原子性：失败不留半成品规则」。
//   网关无 project 删除接口，project/policy 失败时项目会孤立（无规则引用→无人命中，惰性），
//   错误信息会点名孤立 project 供人工清理。
import { AdminError, errMsg } from './errors.js';
function reqStr(obj, key) {
    const v = obj[key];
    if (typeof v !== 'string' || v.trim() === '') {
        throw new AdminError('invalid_request', `字段 ${key} 必填且须为非空字符串`);
    }
    return v.trim();
}
/** 建分组入参校验+归一。允许模型须为非空字符串数组（至少 1 个，避免建出无模型可用的空组）。 */
export function normalizeCreateGroup(input) {
    if (typeof input !== 'object' || input === null) {
        throw new AdminError('invalid_request', '请求体须为 JSON 对象');
    }
    const obj = input;
    const name = reqStr(obj, 'name');
    // 组名用于拼网关 project 名与本地 mappedGroup，限制字符集防注入怪名
    if (!/^[A-Za-z0-9_-]{1,40}$/.test(name)) {
        throw new AdminError('invalid_request', '分组名仅允许字母/数字/下划线/连字符，长度 1-40');
    }
    const department = reqStr(obj, 'department');
    const rawModels = obj.allowModels;
    if (!Array.isArray(rawModels) || rawModels.length === 0) {
        throw new AdminError('invalid_request', '字段 allowModels 须为至少含一个模型名的数组');
    }
    const allowModels = [];
    for (const m of rawModels) {
        if (typeof m !== 'string' || m.trim() === '') {
            throw new AdminError('invalid_request', 'allowModels 内每个模型名须为非空字符串');
        }
        allowModels.push(m.trim());
    }
    let priority = 100;
    if (obj.priority !== undefined && obj.priority !== null) {
        const n = typeof obj.priority === 'number' ? obj.priority : Number(obj.priority);
        if (!Number.isInteger(n) || n < 0)
            throw new AdminError('invalid_request', '字段 priority 须为非负整数');
        priority = n;
    }
    return { name, department, allowModels: Array.from(new Set(allowModels)), priority };
}
export async function createGroup(deps, rawInput) {
    const input = normalizeCreateGroup(rawInput);
    const projectName = `${deps.projectPrefix ?? 'portal-dev-'}${input.name}`;
    // 1) 建网关 project
    let project;
    try {
        project = await deps.createProject(projectName);
    }
    catch (e) {
        throw new AdminError('group_project_failed', `建分组失败：网关项目创建失败：${errMsg(e)}`, 502);
    }
    // 2) 设模型策略 allow（强制点：网关硬拒的依据）
    try {
        await deps.setModelPolicy(project.id, input.allowModels);
    }
    catch (e) {
        throw new AdminError('group_policy_failed', `建分组失败：模型策略设置失败（网关项目 ${project.id} 已创建但无策略、网关无删除接口，需人工清理；未写入任何映射规则）：${errMsg(e)}`, 502);
    }
    // 3) 建本地映射规则（最后一步：此前失败绝不遗留规则）
    let rule;
    try {
        rule = await deps.createRule({
            matchType: 'department',
            matchValue: input.department,
            mappedGroup: input.name,
            gatewayProjectId: project.id,
            priority: input.priority,
            enabled: true,
        });
    }
    catch (e) {
        throw new AdminError('group_rule_failed', `建分组失败：映射规则写入失败（网关项目 ${project.id} 与模型策略已建，需人工清理）：${errMsg(e)}`, 500);
    }
    return {
        mappedGroup: input.name,
        gatewayProjectId: project.id,
        gatewayProjectName: project.name,
        ruleId: rule.id,
        allowModels: input.allowModels,
    };
}
