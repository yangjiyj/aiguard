-- Phase4 阶段B：门户员工↔网关 user/team 打通 + scope 漂移治本
-- 均为可空/带默认列的追加，SQLite 直接 ADD COLUMN（无需重建表），存量行安全回填默认值。

-- AlterTable EmployeeKey：加 gatewayUserId（可空，开关关时恒 null）+ scopeVersion（默认 0＝存量旧 scope）
ALTER TABLE "EmployeeKey" ADD COLUMN "gatewayUserId" TEXT;
ALTER TABLE "EmployeeKey" ADD COLUMN "scopeVersion" INTEGER NOT NULL DEFAULT 0;

-- AlterTable GroupMappingRule：加 gatewayTeamId（可空，首次打通惰性建 team 后回填）
ALTER TABLE "GroupMappingRule" ADD COLUMN "gatewayTeamId" TEXT;
