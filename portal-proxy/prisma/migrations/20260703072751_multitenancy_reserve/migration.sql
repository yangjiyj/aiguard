-- CreateTable
CREATE TABLE "EmployeeRole" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "tenantId" TEXT NOT NULL DEFAULT 'tenant_default',
    "subject" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "role" TEXT NOT NULL DEFAULT 'employee',
    "managedDepartments" TEXT NOT NULL DEFAULT '[]',
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);

-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_EmployeeKey" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "tenantId" TEXT NOT NULL DEFAULT 'tenant_default',
    "lobeUserId" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "ssoSubject" TEXT,
    "gatewayKeyId" TEXT NOT NULL,
    "keyPrefix" TEXT NOT NULL,
    "keyEnc" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'active',
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastUsedAt" DATETIME,
    "mappedGroup" TEXT,
    "gatewayProjectId" TEXT,
    "lastDepartment" TEXT,
    "lastEvaluatedAt" DATETIME
);
INSERT INTO "new_EmployeeKey" ("createdAt", "email", "gatewayKeyId", "gatewayProjectId", "id", "keyEnc", "keyPrefix", "lastDepartment", "lastEvaluatedAt", "lastUsedAt", "lobeUserId", "mappedGroup", "ssoSubject", "status") SELECT "createdAt", "email", "gatewayKeyId", "gatewayProjectId", "id", "keyEnc", "keyPrefix", "lastDepartment", "lastEvaluatedAt", "lastUsedAt", "lobeUserId", "mappedGroup", "ssoSubject", "status" FROM "EmployeeKey";
DROP TABLE "EmployeeKey";
ALTER TABLE "new_EmployeeKey" RENAME TO "EmployeeKey";
CREATE UNIQUE INDEX "EmployeeKey_tenantId_lobeUserId_key" ON "EmployeeKey"("tenantId", "lobeUserId");
CREATE TABLE "new_GroupMappingRule" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "tenantId" TEXT NOT NULL DEFAULT 'tenant_default',
    "matchType" TEXT NOT NULL DEFAULT 'department',
    "matchValue" TEXT NOT NULL,
    "mappedGroup" TEXT NOT NULL,
    "gatewayProjectId" TEXT NOT NULL,
    "priority" INTEGER NOT NULL DEFAULT 100,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);
INSERT INTO "new_GroupMappingRule" ("createdAt", "enabled", "gatewayProjectId", "id", "mappedGroup", "matchType", "matchValue", "priority", "updatedAt") SELECT "createdAt", "enabled", "gatewayProjectId", "id", "mappedGroup", "matchType", "matchValue", "priority", "updatedAt" FROM "GroupMappingRule";
DROP TABLE "GroupMappingRule";
ALTER TABLE "new_GroupMappingRule" RENAME TO "GroupMappingRule";
CREATE INDEX "GroupMappingRule_tenantId_matchType_matchValue_idx" ON "GroupMappingRule"("tenantId", "matchType", "matchValue");
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;

-- CreateIndex
CREATE UNIQUE INDEX "EmployeeRole_tenantId_subject_key" ON "EmployeeRole"("tenantId", "subject");

