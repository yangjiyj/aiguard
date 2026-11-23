// 后台「测试映射」工具（S4）：给一个 department 值，返回它会命中哪条规则、落到哪个分组/网关 project，
// 以及该 project 的允许模型清单（调网关 policies/model）。
// 降级：网关模型策略查询失败（含已知 GET 400 bug）→ allowModels=null、policyAvailable=false，
// 不影响映射判定本身（映射只依赖本地规则表）。
import { evaluateGroup, matchRule } from '../evaluate.js';
export async function resolveTestMapping(deps, department) {
    const rules = await deps.listRules();
    const hit = matchRule(department, rules);
    const assignment = evaluateGroup(department, rules, deps.defaultProjectId);
    let allowModels = null;
    let policyAvailable = false;
    let openPolicy = false;
    try {
        const policy = await deps.getModelPolicy(assignment.gatewayProjectId);
        policyAvailable = true;
        if (policy.allowList.length === 0) {
            openPolicy = true;
            allowModels = [];
        }
        else {
            allowModels = policy.allowList;
        }
    }
    catch {
        // 降级：网关策略查询不可用（例如已知 GET policies/model 400），不阻断映射判定
        policyAvailable = false;
        allowModels = null;
    }
    return {
        department,
        matched: hit !== null,
        matchedRule: hit
            ? {
                matchType: hit.matchType,
                matchValue: hit.matchValue,
                mappedGroup: hit.mappedGroup,
                gatewayProjectId: hit.gatewayProjectId,
                priority: hit.priority,
            }
            : null,
        mappedGroup: assignment.mappedGroup,
        gatewayProjectId: assignment.gatewayProjectId,
        allowModels,
        policyAvailable,
        openPolicy,
    };
}
