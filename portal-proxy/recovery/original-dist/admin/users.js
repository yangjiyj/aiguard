/** 纯映射：DB 行 → 安全视图（无任何 key 密文/明文字段）。 */
export function toUserView(r) {
    return {
        lobeUserId: r.lobeUserId,
        email: r.email,
        mappedGroup: r.mappedGroup,
        gatewayProjectId: r.gatewayProjectId,
        keyPrefix: r.keyPrefix,
        status: r.status,
        lastDepartment: r.lastDepartment,
        lastEvaluatedAt: r.lastEvaluatedAt ? r.lastEvaluatedAt.toISOString() : null,
        lastUsedAt: r.lastUsedAt ? r.lastUsedAt.toISOString() : null,
        createdAt: r.createdAt.toISOString(),
    };
}
export async function listUsers(prisma) {
    const rows = await prisma.employeeKey.findMany({
        orderBy: { createdAt: 'asc' },
        select: {
            lobeUserId: true,
            email: true,
            mappedGroup: true,
            gatewayProjectId: true,
            keyPrefix: true,
            status: true,
            lastDepartment: true,
            lastEvaluatedAt: true,
            lastUsedAt: true,
            createdAt: true,
        },
    });
    return rows.map(toUserView);
}
