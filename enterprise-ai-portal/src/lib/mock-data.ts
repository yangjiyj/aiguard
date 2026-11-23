/**
 * M1 Mock 数据层
 * M2 起改为 Prisma + 真实用户隔离。这里只用 mock 把 UI 跑起来。
 */

export type Role = "employee" | "manager" | "admin";

export type MockUser = {
  sub: string;
  name: string;
  email: string;
  department: string;
  role: Role;
};

export type MockConversation = {
  id: string;
  title: string;
  model: string;
  updatedAt: number; // epoch ms
  messages: MockMessage[];
};

export type MockMessage = {
  id: string;
  role: "user" | "assistant";
  content: string;
  model?: string;
};

/** M1 占位用户（M2 从 SSO 会话取） */
export const mockUser: MockUser = {
  sub: "mock-sub-001",
  name: "张文远",
  email: "zhangwy@example.com",
  department: "信息安全部",
  role: "employee",
};

function ts(daysAgo: number, hour = 10, min = 0) {
  const d = new Date();
  d.setDate(d.getDate() - daysAgo);
  d.setHours(hour, min, 0, 0);
  return d.getTime();
}

export const mockConversations: MockConversation[] = [
  {
    id: "c1",
    title: "零信任架构落地建议",
    model: "glm-5.2",
    updatedAt: ts(0, 14, 30),
    messages: [
      {
        id: "m1",
        role: "user",
        content: "我们公司要推行零信任，第一步该从哪里入手？",
      },
      {
        id: "m2",
        role: "assistant",
        model: "glm-5.2",
        content: `零信任落地的第一步通常是**身份与访问的统一**，而不是急着买设备。建议按这个顺序推进：

1. **梳理资产与身份**：把人、设备、应用、数据列清单，明确"谁在用什么方式访问什么"。
2. **集中身份**：所有应用收口到企业 SSO（OIDC/SAML），去掉本地账号和静态长密钥。
3. **最小权限**：按角色授予最小访问范围，默认拒绝。
4. **分段与持续校验**：网络微分段 + 每次访问都做身份/设备/上下文校验。

> 核心思想：**从不信任，始终校验**。先打通身份这一层，后面的策略才有抓手。`,
      },
    ],
  },
  {
    id: "c2",
    title: "API 安全评审清单",
    model: "glm-5.2",
    updatedAt: ts(0, 9, 12),
    messages: [
      {
        id: "m3",
        role: "user",
        content: "给一份 API 安全评审 checklist",
      },
      {
        id: "m4",
        role: "assistant",
        model: "glm-5.2",
        content: `API 安全评审要点：

| 维度 | 检查项 |
|---|---|
| 认证 | 是否走 OAuth2/OIDC，有无静态长密钥 |
| 授权 | 是否按主体身份做范围限制（服务端强制） |
| 输入 | 是否做了校验与清洗，防注入 |
| 限流 | 是否按用户/租户限流 |
| 审计 | 关键操作是否留痕、可归因到人 |

\`\`\`bash
# 快速自测未授权访问
curl -i https://api.example.com/v1/users/123
\`\`\``,
      },
    ],
  },
  {
    id: "c3",
    title: "周报草稿润色",
    model: "deepseek-v3",
    updatedAt: ts(1, 18, 0),
    messages: [
      {
        id: "m5",
        role: "user",
        content: "帮我把这周报的开头改得更简洁。",
      },
      {
        id: "m6",
        role: "assistant",
        model: "deepseek-v3",
        content: "好的，把原文发我，我来精简。",
      },
    ],
  },
  {
    id: "c4",
    title: "入职安全意识培训大纲",
    model: "glm-4.6",
    updatedAt: ts(3, 11, 20),
    messages: [],
  },
  {
    id: "c5",
    title: "钓鱼邮件演练方案",
    model: "glm-5.2",
    updatedAt: ts(8, 16, 45),
    messages: [],
  },
  {
    id: "c6",
    title: "数据分类分级标准 v2",
    model: "glm-4.6",
    updatedAt: ts(15, 10, 0),
    messages: [],
  },
];
