-- W9 9.6：门户后台服务端可撤销会话。追加建表，不动存量。
-- 升级后旧 portal_id_token cookie 不再被接受，门户管理员需重新登录一次。

-- CreateTable
CREATE TABLE "PortalSession" (
    "idHash" TEXT NOT NULL PRIMARY KEY,
    "tenantId" TEXT NOT NULL DEFAULT 'tenant_default',
    "subject" TEXT NOT NULL,
    "email" TEXT,
    "department" TEXT,
    "idpSid" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" DATETIME NOT NULL,
    "revokedAt" DATETIME
);

-- CreateIndex
CREATE INDEX "PortalSession_tenantId_subject_idx" ON "PortalSession"("tenantId", "subject");

-- CreateIndex
CREATE INDEX "PortalSession_tenantId_idpSid_idx" ON "PortalSession"("tenantId", "idpSid");

-- CreateIndex
CREATE INDEX "PortalSession_expiresAt_idx" ON "PortalSession"("expiresAt");
