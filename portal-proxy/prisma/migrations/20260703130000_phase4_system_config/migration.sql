-- Phase4 阶段C：门户系统配置表（可开可关运行时开关，key-value，多租户预留）。
-- 首用键 gateway_user_sync_enabled，合成开关＝env 放行 AND value="true"。追加建表，不动存量。

-- CreateTable
CREATE TABLE "PortalSystemConfig" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "tenantId" TEXT NOT NULL DEFAULT 'tenant_default',
    "key" TEXT NOT NULL,
    "value" TEXT NOT NULL,
    "updatedAt" DATETIME NOT NULL
);

-- CreateIndex
CREATE UNIQUE INDEX "PortalSystemConfig_tenantId_key_key" ON "PortalSystemConfig"("tenantId", "key");
