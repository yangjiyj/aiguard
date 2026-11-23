-- AlterTable
ALTER TABLE "EmployeeKey" ADD COLUMN "gatewayProjectId" TEXT;
ALTER TABLE "EmployeeKey" ADD COLUMN "lastDepartment" TEXT;
ALTER TABLE "EmployeeKey" ADD COLUMN "lastEvaluatedAt" DATETIME;
ALTER TABLE "EmployeeKey" ADD COLUMN "mappedGroup" TEXT;

-- CreateTable
CREATE TABLE "GroupMappingRule" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "matchType" TEXT NOT NULL DEFAULT 'department',
    "matchValue" TEXT NOT NULL,
    "mappedGroup" TEXT NOT NULL,
    "gatewayProjectId" TEXT NOT NULL,
    "priority" INTEGER NOT NULL DEFAULT 100,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);

-- CreateIndex
CREATE INDEX "GroupMappingRule_matchType_matchValue_idx" ON "GroupMappingRule"("matchType", "matchValue");
